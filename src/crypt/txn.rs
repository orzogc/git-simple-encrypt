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
//! 1. Each destination is hard-linked (or copied) to a sibling backup before
//!    it is replaced, and the pairs are recorded in a journal inside the git
//!    dir, `fsync`ed before anything moves.
//! 2. A failure mid-way restores every backup taken so far, so the operation
//!    is all-or-nothing within the process.
//! 3. A crash leaves the journal behind. The next [`recover`] call — run from
//!    `Repo::open` — puts the originals back, so the repository returns to its
//!    pre-operation state rather than staying half-converted.
//!
//! Recovery always rolls *backwards*. Rolling forward would need the temp
//! files, which do not survive a crash in any dependable way.

use std::path::{Path, PathBuf};

use log::{debug, warn};

use crate::{
    crypt::file::PreparedWrite,
    error::{Error, Result},
    utils::{BACKUP_PREFIX, atomic_write},
};

/// Journal file name inside the git dir.
const JOURNAL_NAME: &str = "git-se-transaction";

/// A phase-two commit that can be undone.
pub(super) struct Transaction {
    journal: PathBuf,
    /// `(destination, backup)` for every file already replaced.
    done: Vec<(PathBuf, PathBuf)>,
}

impl Transaction {
    /// Record the intended replacements and start committing.
    ///
    /// The journal is written and `fsync`ed *before* the first rename, so a
    /// crash can never leave a replaced file whose original is unrecorded.
    pub(super) fn begin(git_dir: &Path, writes: &[PreparedWrite]) -> Result<Self> {
        let journal = git_dir.join(JOURNAL_NAME);
        let mut record = Vec::new();
        for (index, write) in writes.iter().enumerate() {
            record.extend_from_slice(path_bytes(write.destination()).as_ref());
            record.push(0);
            record.extend_from_slice(path_bytes(&backup_path(write.destination(), index)).as_ref());
            record.push(0);
        }
        if let Some(parent) = journal.parent() {
            std::fs::create_dir_all(parent)?;
        }
        atomic_write(&journal, &record)?;
        Ok(Self {
            journal,
            done: Vec::with_capacity(writes.len()),
        })
    }

    /// Replace one destination, keeping a backup so it can be put back.
    pub(super) fn commit_one(&mut self, index: usize, write: PreparedWrite) -> Result<()> {
        let dst = write.destination().to_path_buf();
        let backup = backup_path(&dst, index);
        // A hard link keeps the original reachable at BOTH names, so the
        // destination never blinks out of existence; the rename that follows
        // is atomic. Filesystems without hard links fall back to a copy.
        if let Err(link_err) = std::fs::hard_link(&dst, &backup) {
            let _ = std::fs::remove_file(&backup);
            std::fs::copy(&dst, &backup).map_err(|copy_err| {
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

    /// Every file was replaced: drop the backups and the journal.
    pub(super) fn finish(self) -> Result<()> {
        for (_, backup) in &self.done {
            let _ = std::fs::remove_file(backup);
        }
        // Only now is the operation irrevocable, so the journal goes last.
        std::fs::remove_file(&self.journal)?;
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

/// Roll back an interrupted commit phase, if one is recorded.
///
/// Called when a repository is opened. Returning the repository to its
/// pre-operation state is always safe: every operation here is idempotent, so
/// the user simply re-runs the command.
pub fn recover(git_dir: &Path) {
    let journal = git_dir.join(JOURNAL_NAME);
    let Ok(record) = std::fs::read(&journal) else {
        return; // the common case: no interrupted transaction
    };

    let mut fields = record.split(|&b| b == 0).filter(|s| !s.is_empty());
    let mut restored = 0;
    while let (Some(dst), Some(backup)) = (fields.next(), fields.next()) {
        let (dst, backup) = (bytes_path(dst), bytes_path(backup));
        // Only files that actually got replaced have a backup on disk.
        if backup.exists() && std::fs::rename(&backup, &dst).is_ok() {
            restored += 1;
        }
    }
    if restored > 0 {
        warn!(
            "A previous git-se run was interrupted while replacing files; {restored} file(s) \
             were restored to their pre-run content. Re-run the command to finish."
        );
    }
    if let Err(e) = std::fs::remove_file(&journal) {
        warn!("Could not remove the stale transaction journal: {e}");
    }
}

/// Sibling backup path for `dst`, unique within one batch.
fn backup_path(dst: &Path, index: usize) -> PathBuf {
    let parent = dst.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!("{BACKUP_PREFIX}{index}"))
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
