//! All-or-nothing commit of a batch of prepared writes.
//!
//! Phase one of a repo-wide operation writes every new file into a temp file
//! beside its destination, so a failure there costs nothing. Phase two —
//! renaming those temps into place — used to be a bare loop: a failure on the
//! seventh file left six already replaced and four not, which for a password
//! change is a state no re-run can repair (half the files answer to the old
//! password, half to the new one).
//!
//! This module makes phase two recoverable:
//!
//! 1. Each destination is hard-linked (or atomically copied) to a sibling
//!    backup before it is replaced, and the pairs are recorded in a journal
//!    inside the git dir, `fsync`ed before anything moves.
//! 2. A failure mid-way restores every backup taken so far, so the operation
//!    is all-or-nothing within the process.
//! 3. A crash leaves the journal behind. The next [`recover`] call — run from
//!    `Repo::open`, under the repository lock — puts the originals back, so
//!    the repository returns to its pre-operation state rather than staying
//!    half-converted.
//!
//! Recovery always rolls *backwards*. Rolling forward would need the temp
//! files, which do not survive a crash in any dependable way.
//!
//! Two protocol invariants keep the crash windows consistent:
//!
//! - The journal is the **commit point**: [`Transaction::finish`] deletes it
//!   first and the backups second. While the journal exists, every backup it
//!   references is guaranteed to still exist; once it is gone, recovery is a
//!   no-op and the backups are mere garbage. (Deleting backups first left a
//!   window where the journal outlived them, and recovery then manufactured
//!   exactly the mixed state the transaction exists to prevent.)
//! - A backup name only ever appears **complete**: hard link, or copy to a
//!   temp file + fsync + atomic rename ([`copy_atomic`]). Recovery trusts
//!   `backup.exists()` to mean "complete backup".

use std::path::{Path, PathBuf};

use log::{debug, warn};
use parking_lot::Mutex;

use crate::{
    crypt::file::PreparedWrite,
    error::{Error, Result},
    utils::{BACKUP_PREFIX, atomic_write},
};

/// Journal file name inside the git dir.
const JOURNAL_NAME: &str = "git-se-transaction";

/// Lock file name inside the git dir, held exclusively for the whole process
/// (see [`acquire_repo_lock`]).
const LOCK_NAME: &str = "git-se.lock";

/// A phase-two commit that can be undone.
pub(super) struct Transaction {
    journal: PathBuf,
    /// Random id of this transaction, embedded in every backup name so a new
    /// transaction can never clobber the leftover backups of an old,
    /// incompletely recovered one.
    txn_id: u32,
    /// `(destination, backup)` for every file already replaced.
    done: Vec<(PathBuf, PathBuf)>,
}

impl Transaction {
    /// Record the intended replacements and start committing.
    ///
    /// The journal is written and `fsync`ed *before* the first rename, so a
    /// crash can never leave a replaced file whose original is unrecorded.
    ///
    /// A leftover journal is a hard error: it means recovery (which runs at
    /// `Repo::open` and deletes the journal only on full success) could not
    /// restore everything. Starting a new transaction would overwrite that
    /// record — and with it the knowledge of what still needs manual
    /// attention.
    pub(super) fn begin(git_dir: &Path, writes: &[PreparedWrite]) -> Result<Self> {
        let journal = git_dir.join(JOURNAL_NAME);
        if journal.exists() {
            return Err(Error::Other(format!(
                "a previous git-se transaction could not be fully recovered; restore the \
                 remaining backups listed in {} manually, then remove that journal",
                journal.display()
            )));
        }
        let txn_id: u32 = rand::random();
        let mut record = Vec::new();
        for (index, write) in writes.iter().enumerate() {
            record.extend_from_slice(path_bytes(write.destination()).as_ref());
            record.push(0);
            record.extend_from_slice(
                path_bytes(&backup_path(write.destination(), index, txn_id)).as_ref(),
            );
            record.push(0);
        }
        if let Some(parent) = journal.parent() {
            std::fs::create_dir_all(parent)?;
        }
        atomic_write(&journal, &record)?;
        Ok(Self {
            journal,
            txn_id,
            done: Vec::with_capacity(writes.len()),
        })
    }

    /// Replace one destination, keeping a backup so it can be put back.
    pub(super) fn commit_one(&mut self, index: usize, write: PreparedWrite) -> Result<()> {
        let dst = write.destination().to_path_buf();
        let backup = backup_path(&dst, index, self.txn_id);
        // A hard link keeps the original reachable at BOTH names, so the
        // destination never blinks out of existence; the rename that follows
        // is atomic. Filesystems without hard links fall back to a copy,
        // which must itself be atomic: a crash mid-copy would otherwise
        // leave a truncated backup that recovery would trust as complete.
        if let Err(link_err) = std::fs::hard_link(&dst, &backup) {
            let _ = std::fs::remove_file(&backup);
            copy_atomic(&dst, &backup).map_err(|copy_err| {
                Error::Other(format!(
                    "could not back up {} before replacing it (link: {link_err}; copy: \
                     {copy_err})",
                    dst.display()
                ))
            })?;
        }
        write.commit()?;
        self.done.push((dst, backup));
        Ok(())
    }

    /// Every file was replaced: the operation is now irrevocable, so the
    /// journal — the commit point — goes FIRST, and the backups become
    /// garbage to collect afterwards. A crash before the journal deletion
    /// leaves every backup in place (recovery rolls everything back,
    /// consistent); a crash after it disables recovery entirely (everything
    /// stays replaced, also consistent).
    pub(super) fn finish(self) -> Result<()> {
        std::fs::remove_file(&self.journal)?;
        for (_, backup) in &self.done {
            let _ = std::fs::remove_file(backup);
        }
        Ok(())
    }

    /// Put every already-replaced original back, then clear the journal.
    ///
    /// Best effort by necessity — it runs on an error path — but each failure
    /// is reported so the user knows exactly which files need attention.
    pub(super) fn rollback(self) {
        for (dst, backup) in self.done.iter().rev() {
            if let Err(e) = std::fs::rename(backup, dst) {
                warn!(
                    "Could not restore {} from {}: {e}. The original content is still in the \
                     backup file; move it back manually.",
                    dst.display(),
                    backup.display()
                );
            }
        }
        if let Err(e) = std::fs::remove_file(&self.journal) {
            debug!("Could not remove the transaction journal: {e}");
        }
    }
}

/// The outcome of rolling back an interrupted commit phase.
#[derive(Debug, Default)]
pub struct Recovery {
    /// How many files were restored from their backup.
    pub restored: usize,
    /// `(destination, backup)` pairs that could not be restored. The journal
    /// and these backups are left in place — they are the user's last
    /// recovery material, so the temp-file sweep must not touch backups
    /// while this is non-empty.
    pub failed: Vec<(PathBuf, PathBuf)>,
}

/// Roll back an interrupted commit phase, if one is recorded.
///
/// Called when a repository is opened. Returning the repository to its
/// pre-operation state is always safe: every operation here is idempotent, so
/// the user simply re-runs the command.
///
/// Every restore failure is reported loudly, and the journal is removed only
/// when everything restorable was restored — deleting it unconditionally, as
/// this used to, threw away the record of what still needed manual recovery
/// (and the sweep then deleted the backups too).
#[must_use]
pub fn recover(git_dir: &Path) -> Recovery {
    let journal = git_dir.join(JOURNAL_NAME);
    let Ok(record) = std::fs::read(&journal) else {
        return Recovery::default(); // the common case: no interrupted transaction
    };

    let mut fields = record.split(|&b| b == 0).filter(|s| !s.is_empty());
    let mut recovery = Recovery::default();
    while let (Some(dst), Some(backup)) = (fields.next(), fields.next()) {
        let (dst, backup) = (bytes_path(dst), bytes_path(backup));
        // Only files that actually got replaced have a backup on disk.
        if !backup.exists() {
            continue;
        }
        match std::fs::rename(&backup, &dst) {
            Ok(()) => recovery.restored += 1,
            Err(e) => {
                warn!(
                    "Could not restore {} from {}: {e}. The original content is still in the \
                     backup file; move it back manually.",
                    dst.display(),
                    backup.display()
                );
                recovery.failed.push((dst, backup));
            }
        }
    }
    if recovery.restored > 0 {
        warn!(
            "A previous git-se run was interrupted while replacing files; {} file(s) were \
             restored to their pre-run content. Re-run the command to finish.",
            recovery.restored
        );
    }
    if recovery.failed.is_empty() {
        if let Err(e) = std::fs::remove_file(&journal) {
            warn!("Could not remove the stale transaction journal: {e}");
        }
    } else {
        warn!(
            "{} file(s) could not be restored; keeping the transaction journal and the \
             remaining backups for manual recovery.",
            recovery.failed.len()
        );
    }
    recovery
}

/// Take this repository's lock for the rest of the process lifetime.
///
/// The journal name is fixed, so without mutual exclusion a second git-se
/// process would mistake a *running* transaction for a crashed one:
/// `Repo::open` would "recover" its backups mid-commit and the sweep would
/// delete its temp files. This advisory lock (per-worktree git dir) turns
/// that into a clean fast failure for the second process instead.
///
/// Re-entrant within one process (a library caller may open the same repo
/// repeatedly); released by the OS when the process exits.
pub fn acquire_repo_lock(git_dir: &Path) -> Result<()> {
    use std::sync::OnceLock;

    /// Lock files this process already holds. flock-style locks conflict even
    /// between two file descriptions of the same process, so a repeated
    /// acquisition must be recognized rather than attempted.
    static HELD: OnceLock<Mutex<Vec<PathBuf>>> = OnceLock::new();

    // A plain (non-git) directory has no git dir to lock in; operations
    // there stay as unprotected as they were before the lock existed.
    if !git_dir.is_dir() {
        return Ok(());
    }
    let lock_path = git_dir.join(LOCK_NAME);
    let held = HELD.get_or_init(|| Mutex::new(Vec::new()));
    if held.lock().contains(&lock_path) {
        return Ok(());
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)?;
    // Leaked on purpose: the guard must live until process exit, which is
    // exactly when the OS releases the lock anyway.
    let lock: &'static mut fd_lock::RwLock<std::fs::File> =
        Box::leak(Box::new(fd_lock::RwLock::new(file)));
    match lock.try_write() {
        Ok(guard) => {
            std::mem::forget(guard);
            held.lock().push(lock_path);
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Err(Error::RepoLocked(lock_path)),
        Err(e) => Err(e.into()),
    }
}

/// Sibling backup path for `dst`, unique within one batch and across
/// transactions (the transaction id keeps a new batch from overwriting the
/// leftover backups of an old, incompletely recovered one).
fn backup_path(dst: &Path, index: usize, txn_id: u32) -> PathBuf {
    let parent = dst.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!("{BACKUP_PREFIX}{txn_id:08x}.{index}"))
}

/// Copy `src` to `dst` without `dst` ever existing partially: the content
/// lands in a temp file first (fsynced), then is renamed into place.
/// Recovery trusts `backup.exists()` to mean "complete backup", so a plain
/// `fs::copy` — which can die halfway — is not good enough here.
fn copy_atomic(src: &Path, dst: &Path) -> std::io::Result<()> {
    let dir = dst.parent().unwrap_or_else(|| Path::new("."));
    let mut temp = crate::utils::temp_file_in(dir)?;
    std::io::copy(&mut std::fs::File::open(src)?, &mut temp)?;
    temp.as_file().sync_all()?;
    // `fs::copy` preserves permission bits; keep that parity so a rollback
    // restores the original permissions too.
    let _ = std::fs::set_permissions(temp.path(), std::fs::metadata(src)?.permissions());
    temp.persist(dst).map_err(|e| e.error)?;
    crate::utils::sync_dir(dir);
    Ok(())
}

#[cfg(unix)]
fn path_bytes(path: &Path) -> std::borrow::Cow<'_, [u8]> {
    use std::os::unix::ffi::OsStrExt;
    std::borrow::Cow::Borrowed(path.as_os_str().as_bytes())
}

#[cfg(not(unix))]
fn path_bytes(path: &Path) -> std::borrow::Cow<'_, [u8]> {
    std::borrow::Cow::Owned(path.to_string_lossy().into_owned().into_bytes())
}

#[cfg(unix)]
fn bytes_path(bytes: &[u8]) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;
    PathBuf::from(std::ffi::OsStr::from_bytes(bytes))
}

#[cfg(not(unix))]
fn bytes_path(bytes: &[u8]) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Write `content` to `dir/name` and return the full path.
    fn write_file(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    /// A `PreparedWrite` stand-in is not constructible outside `crypt::file`,
    /// so build the journal + backups state by hand — exactly what
    /// `begin`/`commit_one` would have produced.
    fn craft_journal(git_dir: &Path, pairs: &[(&Path, &Path)]) {
        let mut record = Vec::new();
        for (dst, backup) in pairs {
            record.extend_from_slice(path_bytes(dst).as_ref());
            record.push(0);
            record.extend_from_slice(path_bytes(backup).as_ref());
            record.push(0);
        }
        std::fs::create_dir_all(git_dir).unwrap();
        atomic_write(&git_dir.join(JOURNAL_NAME), &record).unwrap();
    }

    /// A crash mid-commit (journal + all backups present) rolls every file
    /// back to its original content.
    #[test]
    fn test_recover_restores_all_originals() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path();
        let git_dir = root.join(".git");

        let a = write_file(root, "a", b"NEW0");
        let b = write_file(root, "b", b"NEW1");
        let bak_a = write_file(root, ".git-se-bak.11111111.0", b"OLD0");
        let bak_b = write_file(root, ".git-se-bak.11111111.1", b"OLD1");
        craft_journal(&git_dir, &[(&a, &bak_a), (&b, &bak_b)]);

        let recovery = recover(&git_dir);
        assert_eq!(recovery.restored, 2);
        assert!(recovery.failed.is_empty());
        assert_eq!(std::fs::read(&a).unwrap(), b"OLD0");
        assert_eq!(std::fs::read(&b).unwrap(), b"OLD1");
        assert!(!git_dir.join(JOURNAL_NAME).exists());
        assert!(!bak_a.exists() && !bak_b.exists());
    }

    /// A failed restore must keep the journal AND the backup — deleting them
    /// unconditionally used to destroy the last recovery material (and the
    /// sweep then finished the job).
    #[test]
    fn test_recover_failure_keeps_journal_and_backup() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path();
        let git_dir = root.join(".git");

        // Make the restore fail: a non-empty directory now sits at dst, and
        // renaming a file over it fails.
        let dst = root.join("a");
        std::fs::create_dir(&dst).unwrap();
        std::fs::write(dst.join("occupied"), b"x").unwrap();
        let backup = write_file(root, ".git-se-bak.22222222.0", b"OLD0");
        craft_journal(&git_dir, &[(&dst, &backup)]);

        let recovery = recover(&git_dir);
        assert_eq!(recovery.restored, 0);
        assert_eq!(recovery.failed, vec![(dst, backup.clone())]);
        assert!(
            git_dir.join(JOURNAL_NAME).exists(),
            "the journal must survive a failed recovery"
        );
        assert!(backup.exists(), "the backup must survive a failed recovery");
    }

    /// `finish` removes the journal first: after it returns, neither journal
    /// nor backups may remain, and the destinations keep the new content.
    #[test]
    fn test_finish_leaves_no_trace() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path();
        let git_dir = root.join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();

        let dst = write_file(root, "a", b"OLD");
        // Emulate begin() + a completed replacement without PreparedWrite.
        let txn_id: u32 = 0xABCD_1234;
        let backup = backup_path(&dst, 0, txn_id);
        craft_journal(&git_dir, &[(&dst, &backup)]);
        std::fs::hard_link(&dst, &backup).unwrap();
        std::fs::write(&dst, b"NEW").unwrap();

        let txn = Transaction {
            journal: git_dir.join(JOURNAL_NAME),
            txn_id,
            done: vec![(dst.clone(), backup.clone())],
        };
        txn.finish().unwrap();

        assert!(!git_dir.join(JOURNAL_NAME).exists());
        assert!(!backup.exists());
        assert_eq!(std::fs::read(&dst).unwrap(), b"NEW");
    }

    /// `copy_atomic` must produce a complete copy with the source's
    /// permission bits — it is the backup of last resort on filesystems
    /// without hard links.
    #[cfg(unix)]
    #[test]
    fn test_copy_atomic_copies_content_and_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::TempDir::new().unwrap();
        let src = write_file(dir.path(), "src", b"backup me");
        let mut perms = std::fs::metadata(&src).unwrap().permissions();
        perms.set_mode(0o640);
        std::fs::set_permissions(&src, perms).unwrap();

        let dst = dir.path().join(".git-se-bak.33333333.0");
        copy_atomic(&src, &dst).unwrap();

        assert_eq!(std::fs::read(&dst).unwrap(), b"backup me");
        assert_eq!(
            std::fs::metadata(&dst).unwrap().permissions().mode() & 0o777,
            0o640
        );
        // No temp file may be left behind.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    /// A second `acquire_repo_lock` in the same process is a no-op, so a
    /// library caller can open the same repo repeatedly.
    #[test]
    fn test_repo_lock_is_reentrant_in_process() {
        let dir = tempfile::TempDir::new().unwrap();
        let git_dir = dir.path().join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();
        acquire_repo_lock(&git_dir).unwrap();
        acquire_repo_lock(&git_dir).unwrap();
    }
}
