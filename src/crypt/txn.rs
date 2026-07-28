//! All-or-nothing commit of a batch of prepared writes.
//!
//! Phase one of a repo-wide operation writes every new file into a temp file
//! beside its destination, so a failure there costs nothing. Phase two —
//! renaming those temps into place — used to be a bare loop: a failure on the
//! seventh file left six already replaced and four not, which for a password
//! change is a state no re-run can repair (half the files answer to the old
//! password, half to the new one).
//!
//! This module makes phase two recoverable. Protocol (v3):
//!
//! 1. [`Transaction::begin`] backs up **every** destination first (hard link,
//!    or an atomic copy where links are unsupported) and fsyncs the backup
//!    directories. Only then is the journal — listing all `(destination,
//!    backup)` pairs behind a version marker — written and `fsync`ed.
//! 2. [`Transaction::commit_one`] replaces one destination per call. A
//!    failure rolls the replaced files back from their backups.
//! 3. [`Transaction::finish`] deletes the journal **first** (and fsyncs that
//!    deletion), then the backups. The journal is the commit point: while it
//!    exists, every backup it references is guaranteed to exist too, so a
//!    missing backup is an anomaly recovery fails closed on.
//! 4. A crash leaves the journal behind. The next [`recover`] call — run
//!    from `Repo::open`, under the repository lock — puts the originals
//!    back, so the repository returns to its pre-operation state.
//!
//! Recovery always rolls *backwards*. Rolling forward would need the temp
//! files, which do not survive a crash in any dependable way.
//!
//! Journals written by the previous protocol (backups taken per file *during*
//! the commit, journal first) carry no version marker; [`recover`] keeps the
//! old semantics for them (a missing backup simply means "never replaced").

use std::{
    path::{Path, PathBuf},
    sync::{Arc, OnceLock, Weak},
};

use log::{debug, warn};
use parking_lot::Mutex;

use crate::{
    crypt::file::PreparedWrite,
    error::{Error, Result},
    utils::{BACKUP_PREFIX, atomic_write},
};

/// Journal file name inside the git dir.
const JOURNAL_NAME: &str = "git-se-transaction";

/// Lock file name inside the git dir, held exclusively while a `Repo` is
/// open (see [`acquire_repo_lock`]).
const LOCK_NAME: &str = "git-se.lock";

/// Version marker written as the journal's first field. `v3` means every
/// backup existed (and was durable) before the journal was written, so
/// recovery can treat a missing backup as an anomaly. Journals without the
/// marker come from the per-file backup protocol and keep those semantics.
const JOURNAL_VERSION: &[u8] = b"v3";

/// A phase-two commit that can be undone.
pub(super) struct Transaction {
    journal: PathBuf,
    /// Backup path per write index, all created up front in [`Transaction::begin`].
    backups: Vec<PathBuf>,
    /// `(destination, backup)` for every file already replaced.
    done: Vec<(PathBuf, PathBuf)>,
}

impl Transaction {
    /// Back up every destination, then record the intended replacements and
    /// start committing.
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
        let txn_id: u128 = rand::random();

        // Step 1: back up EVERY destination before anything is replaced.
        // Only when all backups exist does the journal come into being, so
        // "journal present" implies "every journaled backup existed at
        // journal time" — recovery never has to guess whether a file with a
        // missing backup was replaced or not.
        let mut backups = Vec::with_capacity(writes.len());
        for (index, write) in writes.iter().enumerate() {
            let dst = write.destination();
            let backup = backup_path(dst, index, txn_id);
            // A hard link keeps the original reachable at BOTH names.
            // Filesystems without hard links fall back to a copy, which must
            // itself be atomic: a crash mid-copy would otherwise leave a
            // truncated backup that recovery would trust as complete.
            if let Err(link_err) = std::fs::hard_link(dst, &backup) {
                let _ = std::fs::remove_file(&backup);
                if let Err(copy_err) = copy_atomic(dst, &backup) {
                    // Nothing was replaced and no journal exists, so the
                    // partial backups are mere garbage: drop them and fail.
                    for created in &backups {
                        let _ = std::fs::remove_file(created);
                    }
                    return Err(Error::Other(format!(
                        "could not back up {} before replacing it (link: {link_err}; copy: \
                         {copy_err}); nothing was replaced",
                        dst.display()
                    )));
                }
            }
            backups.push(backup);
        }
        // Make the backups durable before the journal points at them: one
        // fsync per distinct parent directory (hard links create no file
        // content to sync; `copy_atomic` already synced its own).
        let mut parents: Vec<&Path> = backups.iter().filter_map(|b| b.parent()).collect();
        parents.sort_unstable();
        parents.dedup();
        for parent in parents {
            crate::utils::sync_dir(parent);
        }

        // Step 2: the journal, fsynced (via `atomic_write`) before anything
        // moves, so a crash can never leave a replaced file whose original
        // is unrecorded.
        let mut record = Vec::new();
        record.extend_from_slice(JOURNAL_VERSION);
        record.push(0);
        for (write, backup) in writes.iter().zip(&backups) {
            record.extend_from_slice(path_bytes(write.destination()).as_ref());
            record.push(0);
            record.extend_from_slice(path_bytes(backup).as_ref());
            record.push(0);
        }
        if let Some(parent) = journal.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if let Err(e) = atomic_write(&journal, &record) {
            for created in &backups {
                let _ = std::fs::remove_file(created);
            }
            return Err(e);
        }
        Ok(Self {
            journal,
            backups,
            done: Vec::with_capacity(writes.len()),
        })
    }

    /// Replace one destination. Its backup already exists (created and
    /// persisted in [`Transaction::begin`]).
    pub(super) fn commit_one(&mut self, index: usize, write: PreparedWrite) -> Result<()> {
        let dst = write.destination().to_path_buf();
        let backup = self.backups[index].clone();
        write.commit()?;
        self.done.push((dst, backup));
        Ok(())
    }

    /// Every file was replaced: the operation is now irrevocable, so the
    /// journal — the commit point — goes FIRST, and its deletion is fsynced
    /// before the backups become garbage. A power cut must not resurrect the
    /// journal while some backup deletions did persist (recovery would then
    /// see a journal referencing missing backups, an anomaly it fails closed
    /// on).
    pub(super) fn finish(self) -> Result<()> {
        std::fs::remove_file(&self.journal)?;
        if let Some(parent) = self.journal.parent() {
            crate::utils::sync_dir(parent);
        }
        for backup in &self.backups {
            let _ = std::fs::remove_file(backup);
        }
        Ok(())
    }

    /// Put every already-replaced original back.
    ///
    /// Best effort by necessity — it runs on an error path — but every
    /// failure is reported, and on any failure the journal is REWRITTEN to
    /// exactly the pairs that still need recovery and kept: deleting it
    /// unconditionally, as this used to, left new content in place with no
    /// record of which backups hold the originals.
    pub(super) fn rollback(self) -> Recovery {
        let mut recovery = Recovery::default();
        for (dst, backup) in self.done.iter().rev() {
            match std::fs::rename(backup, dst) {
                Ok(()) => recovery.restored += 1,
                Err(e) => {
                    warn!(
                        "Could not restore {} from {}: {e}. The original content is still in \
                         the backup file; move it back manually.",
                        dst.display(),
                        backup.display()
                    );
                    recovery.failed.push((dst.clone(), backup.clone()));
                }
            }
        }
        if recovery.failed.is_empty() {
            // Full rollback: leftover backups (from writes never replaced)
            // are garbage, and the journal goes too.
            for backup in &self.backups {
                let _ = std::fs::remove_file(backup);
            }
            if let Err(e) = std::fs::remove_file(&self.journal) {
                debug!("Could not remove the transaction journal: {e}");
            }
        } else {
            // Partial rollback. The journal must keep pointing at exactly the
            // pairs still needing recovery: a consumed backup looks
            // "missing", and a v3 journal with a missing backup is an
            // anomaly the next `recover` fails closed on. Backups of pairs
            // that need no recovery are garbage and go now.
            let failed: Vec<&Path> = recovery
                .failed
                .iter()
                .map(|(_, backup)| backup.as_path())
                .collect();
            for backup in &self.backups {
                if !failed.contains(&backup.as_path()) {
                    let _ = std::fs::remove_file(backup);
                }
            }
            self.rewrite_journal(&recovery.failed);
            warn!(
                "{} file(s) could not be rolled back; the transaction journal and their \
                 backups were kept — the next git-se command will retry the restore.",
                recovery.failed.len()
            );
        }
        recovery
    }

    /// Rewrite the journal to exactly `pairs` (v3 format). On failure the
    /// original journal stays, which keeps recovery conservative.
    fn rewrite_journal(&self, pairs: &[(PathBuf, PathBuf)]) {
        let mut record = Vec::new();
        record.extend_from_slice(JOURNAL_VERSION);
        record.push(0);
        for (dst, backup) in pairs {
            record.extend_from_slice(path_bytes(dst).as_ref());
            record.push(0);
            record.extend_from_slice(path_bytes(backup).as_ref());
            record.push(0);
        }
        if let Err(e) = atomic_write(&self.journal, &record) {
            warn!("Could not rewrite the transaction journal: {e}");
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

    let mut fields = record
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .peekable();
    // See JOURNAL_VERSION: v3 journals were written only after every backup
    // existed, so a missing backup can only mean external deletion or a
    // power-cut resurrection — fail closed. Unversioned (v2) journals took
    // backups per file during the commit, where a missing backup simply
    // means "never replaced" and is safe to skip. The marker is PEEKED, not
    // consumed unconditionally: a v2 journal's first field is a destination
    // path, and eating it would shift every pair out of alignment.
    let v3 = fields.peek().is_some_and(|f| *f == JOURNAL_VERSION);
    if v3 {
        fields.next();
    }
    let mut recovery = Recovery::default();
    while let (Some(dst), Some(backup)) = (fields.next(), fields.next()) {
        let (dst, backup) = (bytes_path(dst), bytes_path(backup));
        if !backup.exists() {
            if v3 {
                warn!(
                    "The transaction journal references a backup that no longer exists: {}. \
                     {} may already hold new content — verify it manually. The journal is \
                     kept for manual recovery.",
                    backup.display(),
                    dst.display()
                );
                recovery.failed.push((dst, backup));
            }
            continue;
        }
        match std::fs::rename(&backup, &dst) {
            Ok(()) => recovery.restored += 1,
            Err(e) => {
                warn!(
                    "Could not restore {} from {}: {e}. The original content is still in \
                     the backup file; move it back manually.",
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
        } else {
            crate::utils::sync_dir(git_dir);
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

/// Handle to a held repository lock.
///
/// The lock is released when the last handle drops (its file is closed), so
/// a library user is not stuck holding repositories until process exit, and
/// a long-lived process does not leak a file descriptor per repository
/// forever.
#[derive(Debug)]
pub struct RepoLock {
    path: PathBuf,
    file: std::fs::File,
}

impl Drop for RepoLock {
    fn drop(&mut self) {
        // Called through the trait explicitly: inherent `File::unlock`
        // (std, newer toolchains) must not shadow fs4's — the lock was
        // taken via fs4 and is released via fs4.
        let _ = fs4::FileExt::unlock(&self.file);
        // Prune the registry entry so a later open re-acquires cleanly.
        if let Some(registry) = HELD_LOCKS.get() {
            registry
                .lock()
                .retain(|(path, weak)| path != &self.path && weak.upgrade().is_some());
        }
    }
}

/// Registry of lock handles this process holds: lock-file path → weak
/// handle. flock-style locks conflict even between two file descriptions
/// of the same process, so a repeated open of the same repository must
/// reuse the existing handle rather than attempt a fresh one.
type LockRegistry = Mutex<Vec<(PathBuf, Weak<RepoLock>)>>;
static HELD_LOCKS: OnceLock<LockRegistry> = OnceLock::new();

/// Take this repository's lock.
///
/// The journal name is fixed, so without mutual exclusion a second git-se
/// process would mistake a *running* transaction for a crashed one:
/// `Repo::open` would "recover" its backups mid-commit and the sweep would
/// delete its temp files. This advisory lock (per-worktree git dir) turns
/// that into a clean fast failure for the second process instead.
///
/// The returned handle keeps the lock; re-opening the same repository in
/// this process hands back a shared handle, and the lock is released when
/// the last handle drops (or when the process exits, at the latest).
pub fn acquire_repo_lock(git_dir: &Path) -> Result<Option<Arc<RepoLock>>> {
    // A plain (non-git) directory has no git dir to lock in; operations
    // there stay as unprotected as they were before the lock existed.
    if !git_dir.is_dir() {
        return Ok(None);
    }
    let lock_path = git_dir.join(LOCK_NAME);
    {
        let registry = HELD_LOCKS.get_or_init(|| Mutex::new(Vec::new()));
        let mut held = registry.lock();
        held.retain(|(_, weak)| weak.upgrade().is_some());
        if let Some(lock) = held
            .iter()
            .find(|(path, _)| path == &lock_path)
            .and_then(|(_, weak)| weak.upgrade())
        {
            return Ok(Some(lock));
        }
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)?;
    // Called through the trait explicitly: the inherent `File::try_lock`
    // (std, newer toolchains) would otherwise shadow fs4's — and they
    // report WouldBlock differently.
    match fs4::FileExt::try_lock(&file) {
        Ok(()) => {
            let lock = Arc::new(RepoLock {
                path: lock_path.clone(),
                file,
            });
            HELD_LOCKS
                .get_or_init(|| Mutex::new(Vec::new()))
                .lock()
                .push((lock_path, Arc::downgrade(&lock)));
            Ok(Some(lock))
        }
        Err(fs4::TryLockError::WouldBlock) => Err(Error::RepoLocked(lock_path)),
        Err(fs4::TryLockError::Error(e)) => Err(e.into()),
    }
}

/// Sibling backup path for `dst`, unique within one batch and across
/// transactions (the 128-bit transaction id keeps a new batch from ever
/// overwriting the leftover backups of an old, incompletely recovered one —
/// and makes the name unmistakably git-se's for the sweep).
fn backup_path(dst: &Path, index: usize, txn_id: u128) -> PathBuf {
    let parent = dst.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!("{BACKUP_PREFIX}{txn_id:032x}.{index}"))
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
    use tempfile::NamedTempFile;

    use super::*;
    use crate::crypt::header::SALT_LEN;

    /// Write `content` to `dir/name` and return the full path.
    fn write_file(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    /// Build a journal file by hand, in the v2 (unversioned) format.
    fn craft_journal_v2(git_dir: &Path, pairs: &[(&Path, &Path)]) {
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

    /// Build a journal file by hand, in the current (v3) format.
    fn craft_journal_v3(git_dir: &Path, pairs: &[(&Path, &Path)]) {
        let mut record = Vec::new();
        record.extend_from_slice(JOURNAL_VERSION);
        record.push(0);
        for (dst, backup) in pairs {
            record.extend_from_slice(path_bytes(dst).as_ref());
            record.push(0);
            record.extend_from_slice(path_bytes(backup).as_ref());
            record.push(0);
        }
        std::fs::create_dir_all(git_dir).unwrap();
        atomic_write(&git_dir.join(JOURNAL_NAME), &record).unwrap();
    }

    /// A minimal `PreparedWrite` over a real file, for driving
    /// `begin`/`commit_one` without the full encrypt pipeline.
    fn prepared_write(dir: &Path, dst: &Path, content: &[u8]) -> PreparedWrite {
        let mut temp = NamedTempFile::new_in(dir).unwrap();
        std::io::Write::write_all(&mut temp, content).unwrap();
        PreparedWrite::for_testing(temp, dst.to_path_buf(), [0x42; SALT_LEN])
    }

    /// A crash mid-commit (journal + all backups present) rolls every file
    /// back to its original content — for a v2 (legacy) journal.
    #[test]
    fn test_recover_restores_all_originals() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path();
        let git_dir = root.join(".git");

        let a = write_file(root, "a", b"NEW0");
        let b = write_file(root, "b", b"NEW1");
        let bak_a = write_file(root, ".git-se-bak.11111111.0", b"OLD0");
        let bak_b = write_file(root, ".git-se-bak.11111111.1", b"OLD1");
        craft_journal_v2(&git_dir, &[(&a, &bak_a), (&b, &bak_b)]);

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
        craft_journal_v2(&git_dir, &[(&dst, &backup)]);

        let recovery = recover(&git_dir);
        assert_eq!(recovery.restored, 0);
        assert_eq!(recovery.failed, vec![(dst, backup.clone())]);
        assert!(
            git_dir.join(JOURNAL_NAME).exists(),
            "the journal must survive a failed recovery"
        );
        assert!(backup.exists(), "the backup must survive a failed recovery");
    }

    /// v2 (legacy) semantics: a missing backup simply means "never
    /// replaced", so it is skipped — the file keeps its current content.
    #[test]
    fn test_recover_v2_skips_missing_backup() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path();
        let git_dir = root.join(".git");

        let a = write_file(root, "a", b"NEW0");
        let b = write_file(root, "b", b"NEW1");
        let bak_b = write_file(root, ".git-se-bak.33333333.1", b"OLD1");
        craft_journal_v2(
            &git_dir,
            &[(&a, &root.join(".git-se-bak.33333333.0")), (&b, &bak_b)],
        );

        let recovery = recover(&git_dir);
        assert_eq!(recovery.restored, 1);
        assert!(recovery.failed.is_empty());
        assert_eq!(std::fs::read(&a).unwrap(), b"NEW0");
        assert_eq!(std::fs::read(&b).unwrap(), b"OLD1");
        assert!(!git_dir.join(JOURNAL_NAME).exists());
    }

    /// v3 semantics: the journal was written only after every backup
    /// existed, so a missing backup is an anomaly — fail closed, keep the
    /// journal, and do not touch anything.
    #[test]
    fn test_recover_v3_missing_backup_fails_closed() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path();
        let git_dir = root.join(".git");

        let a = write_file(root, "a", b"NEW0");
        let b = write_file(root, "b", b"NEW1");
        let bak_b = write_file(
            root,
            ".git-se-bak.44444444444444444444444444444444.1",
            b"OLD1",
        );
        craft_journal_v3(
            &git_dir,
            &[
                (
                    &a,
                    &root.join(".git-se-bak.44444444444444444444444444444444.0"),
                ),
                (&b, &bak_b),
            ],
        );

        let recovery = recover(&git_dir);
        // The present backup IS restored (that file's original is known)...
        assert_eq!(std::fs::read(&b).unwrap(), b"OLD1");
        // ...but the missing one is an anomaly: reported, untouched, and the
        // journal stays for manual recovery.
        assert_eq!(recovery.restored, 1);
        assert_eq!(recovery.failed.len(), 1);
        assert_eq!(std::fs::read(&a).unwrap(), b"NEW0");
        assert!(git_dir.join(JOURNAL_NAME).exists());
    }

    /// `begin` must create every backup BEFORE writing the journal, and
    /// `finish` must leave neither journal nor backups behind.
    #[test]
    fn test_begin_backs_up_everything_before_journaling() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path();
        let git_dir = root.join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();

        let a = write_file(root, "a", b"OLD_A");
        let b = write_file(root, "b", b"OLD_B");
        let writes = vec![
            prepared_write(root, &a, b"NEW_A"),
            prepared_write(root, &b, b"NEW_B"),
        ];

        let mut txn = Transaction::begin(&git_dir, &writes).unwrap();
        // All backups exist already, and the journal is v3-versioned.
        assert_eq!(txn.backups.len(), 2);
        for backup in &txn.backups {
            assert!(backup.exists());
        }
        let journal = std::fs::read(git_dir.join(JOURNAL_NAME)).unwrap();
        assert!(journal.starts_with(b"v3\0"));

        for (index, write) in writes.into_iter().enumerate() {
            txn.commit_one(index, write).unwrap();
        }
        assert_eq!(std::fs::read(&a).unwrap(), b"NEW_A");
        assert_eq!(std::fs::read(&b).unwrap(), b"NEW_B");

        txn.finish().unwrap();
        assert!(!git_dir.join(JOURNAL_NAME).exists());
        assert!(std::fs::read_dir(root).unwrap().all(|e| {
            !e.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(BACKUP_PREFIX)
        }));
    }

    /// A commit-phase failure rolls everything back; a SUCCESSFUL rollback
    /// removes journal and backups.
    #[test]
    fn test_commit_failure_rolls_back_cleanly() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path();
        let git_dir = root.join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();

        let a = write_file(root, "a", b"OLD_A");
        let b = write_file(root, "b", b"OLD_B");
        let writes = vec![
            prepared_write(root, &a, b"NEW_A"),
            prepared_write(root, &b, b"NEW_B"),
        ];
        let mut txn = Transaction::begin(&git_dir, &writes).unwrap();
        let mut writes = writes.into_iter();
        txn.commit_one(0, writes.next().unwrap()).unwrap();

        // Make the second replacement impossible...
        std::fs::remove_file(&b).unwrap();
        std::fs::create_dir(&b).unwrap();
        std::fs::write(b.join("occupied"), b"x").unwrap();
        let second = writes.next().unwrap();
        assert!(txn.commit_one(1, second).is_err());

        let recovery = txn.rollback();
        assert!(recovery.failed.is_empty());
        assert_eq!(std::fs::read(&a).unwrap(), b"OLD_A");
        assert!(!git_dir.join(JOURNAL_NAME).exists());
        assert!(std::fs::read_dir(root).unwrap().all(|e| {
            !e.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(BACKUP_PREFIX)
        }));
    }

    /// A FAILED rollback must keep the journal (rewritten to the failed
    /// pairs) and the failed backups — and the next `recover` must be able
    /// to finish the job.
    #[test]
    fn test_failed_rollback_keeps_journal_for_next_recover() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path();
        let git_dir = root.join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();

        let a = write_file(root, "a", b"OLD_A");
        let writes = vec![prepared_write(root, &a, b"NEW_A")];
        let mut txn = Transaction::begin(&git_dir, &writes).unwrap();
        txn.commit_one(0, writes.into_iter().next().unwrap())
            .unwrap();
        assert_eq!(std::fs::read(&a).unwrap(), b"NEW_A");

        // Make the rollback's rename fail: a non-empty directory at dst.
        std::fs::remove_file(&a).unwrap();
        std::fs::create_dir(&a).unwrap();
        std::fs::write(a.join("occupied"), b"x").unwrap();

        let backup = txn.backups[0].clone();
        let recovery = txn.rollback();
        assert_eq!(recovery.failed.len(), 1);
        assert!(
            git_dir.join(JOURNAL_NAME).exists(),
            "a failed rollback must keep the journal"
        );
        assert!(backup.exists(), "a failed rollback must keep the backup");

        // The next `recover` (after the obstruction is gone) finishes it.
        std::fs::remove_dir_all(&a).unwrap();
        let recovery = recover(&git_dir);
        assert_eq!(recovery.restored, 1);
        assert!(recovery.failed.is_empty());
        assert_eq!(std::fs::read(&a).unwrap(), b"OLD_A");
        assert!(!git_dir.join(JOURNAL_NAME).exists());
    }

    /// `begin` refuses to start over an unrecovered journal.
    #[test]
    fn test_begin_refuses_leftover_journal() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path();
        let git_dir = root.join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();
        atomic_write(&git_dir.join(JOURNAL_NAME), b"v3\0").unwrap();

        let a = write_file(root, "a", b"OLD_A");
        let writes = vec![prepared_write(root, &a, b"NEW_A")];
        assert!(Transaction::begin(&git_dir, &writes).is_err());
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

        let dst = dir
            .path()
            .join(".git-se-bak.55555555555555555555555555555555.0");
        copy_atomic(&src, &dst).unwrap();

        assert_eq!(std::fs::read(&dst).unwrap(), b"backup me");
        assert_eq!(
            std::fs::metadata(&dst).unwrap().permissions().mode() & 0o777,
            0o640
        );
        // No temp file may be left behind.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    /// Lock handles are shared in-process, and dropping the last one
    /// releases the lock so it can be taken again (fresh, by simulating a
    /// second handle owner via the filesystem).
    #[test]
    fn test_repo_lock_shared_and_released() {
        let dir = tempfile::TempDir::new().unwrap();
        let git_dir = dir.path().join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();

        let first = acquire_repo_lock(&git_dir).unwrap().unwrap();
        let second = acquire_repo_lock(&git_dir).unwrap().unwrap();
        assert!(Arc::ptr_eq(&first, &second), "same repo, same handle");

        drop(first);
        drop(second);
        // After the last handle dropped, a new acquisition succeeds and is a
        // fresh handle.
        let third = acquire_repo_lock(&git_dir).unwrap().unwrap();
        assert!(git_dir.join(LOCK_NAME).exists());
        drop(third);
    }
}
