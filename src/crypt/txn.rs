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
//!    directories (strictly — a failed sync aborts the transaction). Only
//!    then is the journal — listing all `(destination, backup)` pairs behind
//!    a version marker — written and `fsync`ed. Paths are recorded relative
//!    to the worktree root, so a repository moved after a crash still
//!    recovers.
//! 2. [`Transaction::commit_one`] replaces one destination per call. A
//!    failure rolls the replaced files back from their backups.
//! 3. [`Transaction::finish`] first fsyncs every replaced destination's
//!    directory (strictly — a power cut must not silently undo a committed
//!    replacement), then deletes the journal and fsyncs THAT deletion, and
//!    only then the backups. The journal is the commit point: while it
//!    exists, every backup it references is guaranteed to exist too, so a
//!    missing backup is an anomaly recovery fails closed on. A backup that
//!    cannot be removed is reported to the caller (after an encrypt it holds
//!    plaintext) — never silently dropped.
//! 4. A crash leaves the journal behind. The next [`recover`] call — run
//!    from `Repo::open`, under the repository lock — puts the originals
//!    back, so the repository returns to its pre-operation state.
//!
//! Recovery always rolls *backwards*. Rolling forward would need the temp
//! files, which do not survive a crash in any dependable way.
//!
//! Restoring **copies** a backup over its destination (atomically, with a
//! strict directory sync) instead of renaming it: the backup is never
//! consumed, so "journal present ⇒ every journaled backup present" holds
//! continuously — even if the machine dies mid-recovery, the next run simply
//! redoes the same idempotent copies. (A rename-based restore used to eat
//! the backup before the journal caught up, and a crash in that window
//! re-flagged the restored pair as a missing-backup anomaly forever.)
//! Backups are deleted only after the journal they answer to is gone
//! (deleted, or rewritten to exclude them).
//!
//! The journal is parsed strictly: an unknown version marker or a truncated
//! record is reported as corruption and left untouched — never interpreted
//! on a guess (a guessed parse once renamed real files out of the tree).
//!
//! Journals written by the previous protocol (backups taken per file *during*
//! the commit, journal first) carry no version marker; [`recover`] keeps the
//! old semantics for them (a missing backup simply means "never replaced" —
//! but only while the missing ones form a contiguous suffix; a gap is an
//! anomaly). Journals with absolute paths (written before relative-path
//! recording) are still honored, but only after full lexical normalization
//! and re-validation that they point inside the worktree being recovered.

use std::{
    path::{Path, PathBuf},
    sync::{Arc, OnceLock, Weak},
};

use log::warn;
use parking_lot::Mutex;

use crate::{
    crypt::file::PreparedWrite,
    error::{Error, Result},
    utils::{BACKUP_PREFIX, atomic_write_durable, sync_dir_strict},
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

/// The transaction journal's path for `git_dir` (error messages need it).
pub fn journal_path(git_dir: &Path) -> PathBuf {
    git_dir.join(JOURNAL_NAME)
}

/// A phase-two commit that can be undone.
pub(super) struct Transaction {
    journal: PathBuf,
    /// The worktree the journaled paths are recorded relative to.
    worktree_root: PathBuf,
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
    pub(super) fn begin(
        git_dir: &Path,
        worktree_root: &Path,
        writes: &[PreparedWrite],
    ) -> Result<Self> {
        let journal = git_dir.join(JOURNAL_NAME);
        // `symlink_metadata`, not `exists`: `exists()` follows links (a
        // dangling symlink reads as absent) and folds metadata errors into
        // "absent" — both would let a new journal overwrite an existing one.
        match std::fs::symlink_metadata(&journal) {
            Ok(_) => {
                return Err(Error::Other(format!(
                    "a previous git-se transaction could not be fully recovered; restore the \
                     remaining backups listed in {} manually, then remove that journal",
                    journal.display()
                )));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(Error::Other(format!(
                    "could not inspect the transaction journal path {} ({e}); refusing to start \
                     a transaction without knowing whether a previous one is unresolved",
                    journal.display()
                )));
            }
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
        // content to sync; `copy_atomic` already synced its own). Strict: a
        // failed sync aborts the transaction rather than silently weakening
        // the power-loss guarantee the journal protocol claims.
        let mut parents: Vec<&Path> = backups.iter().filter_map(|b| b.parent()).collect();
        parents.sort_unstable();
        parents.dedup();
        for parent in parents {
            if let Err(e) = sync_dir_strict(parent) {
                for created in &backups {
                    let _ = std::fs::remove_file(created);
                }
                return Err(Error::Other(format!(
                    "could not make the backups in {} durable ({e}); nothing was replaced",
                    parent.display()
                )));
            }
        }

        // Step 2: the journal, fsynced (via `atomic_write_durable`) before
        // anything moves, so a crash can never leave a replaced file whose
        // original is unrecorded.
        let record = build_journal_record(
            worktree_root,
            writes.iter().map(PreparedWrite::destination).zip(&backups),
        );
        if let Some(parent) = journal.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if let Err(e) = atomic_write_durable(&journal, &record) {
            // The write may have failed at the final directory sync — AFTER
            // the rename already landed. A journal that exists while its
            // backups are deleted is the worst state this protocol has (the
            // next open reports a missing-backup anomaly although nothing
            // was ever replaced), so whenever the journal might be there,
            // the backups stay: together they are valid recovery material.
            if journal.exists() {
                return Err(Error::Other(format!(
                    "could not make the transaction journal durable ({e}); nothing was replaced. \
                     The journal and all backups were left in place as valid recovery material \
                     — re-run any git-se command to roll back, or remove {} and the \
                     {BACKUP_PREFIX}* files manually",
                    journal.display()
                )));
            }
            for created in &backups {
                let _ = std::fs::remove_file(created);
            }
            return Err(e);
        }
        Ok(Self {
            journal,
            worktree_root: worktree_root.to_path_buf(),
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
    ///
    /// Returns the backups that could not be removed. After an encrypt those
    /// hold **plaintext**, so a removal failure is reported to the caller,
    /// never silently dropped: an ignored error here used to leave plaintext
    /// behind while the command reported full success.
    pub(super) fn finish(self) -> Result<Vec<PathBuf>> {
        // Step 1: make every committed replacement durable. Without this a
        // power cut after step 2 could silently revert some destinations to
        // their pre-transaction content while the journal and backups are
        // already gone — a half-reverted repository nobody can detect. A
        // failed sync keeps the journal and the backups, so the next
        // `recover` still has everything it needs to roll back.
        let mut parents: Vec<&Path> = self
            .done
            .iter()
            .filter_map(|(dst, _)| dst.parent())
            .collect();
        parents.sort_unstable();
        parents.dedup();
        for parent in parents {
            if let Err(e) = sync_dir_strict(parent) {
                return Err(Error::Other(format!(
                    "the transaction committed, but the replacements in {} could not be made \
                     durable ({e}); the journal and all backups were left in place — re-run \
                     any git-se command to roll back, then retry",
                    parent.display()
                )));
            }
        }
        // Step 2: the journal — the commit point — goes first, and its
        // deletion must be durable BEFORE any backup goes: a power cut that
        // resurrects the journal while backup deletions persisted is exactly
        // the missing-backup anomaly recovery fails closed on.
        std::fs::remove_file(&self.journal)?;
        if let Some(parent) = self.journal.parent()
            && let Err(e) = sync_dir_strict(parent)
        {
            return Err(Error::Other(format!(
                "the transaction committed, but the journal's deletion could not be made \
                 durable ({e}); the backups were left in place as a precaution — verify the \
                 files, then remove the {BACKUP_PREFIX}* files manually"
            )));
        }
        // Step 3: the backups are garbage now. Their removal is synced too:
        // a power cut must not resurrect a backup whose deletion reported
        // success — after an encrypt it holds PLAINTEXT. A failed directory
        // sync makes every "removed" backup in that directory suspect, so
        // they are reported as unremoved (they may reappear).
        let mut unremoved = Vec::new();
        let mut parents: Vec<&Path> = Vec::new();
        for backup in &self.backups {
            match std::fs::remove_file(backup) {
                Ok(()) => {
                    if let Some(parent) = backup.parent() {
                        parents.push(parent);
                    }
                }
                Err(e) => {
                    warn!(
                        "Could not remove backup {} after a successful commit: {e}",
                        backup.display()
                    );
                    unremoved.push(backup.clone());
                }
            }
        }
        parents.sort_unstable();
        parents.dedup();
        for parent in parents {
            if let Err(e) = sync_dir_strict(parent) {
                warn!(
                    "Backups in {} were removed, but the removal could not be made durable \
                     ({e}); they may reappear after a power cut",
                    parent.display()
                );
                let suspect: Vec<PathBuf> = self
                    .backups
                    .iter()
                    .filter(|b| b.parent() == Some(parent) && !unremoved.contains(b))
                    .cloned()
                    .collect();
                unremoved.extend(suspect);
            }
        }
        Ok(unremoved)
    }

    /// Put every already-replaced original back.
    ///
    /// Restores COPY the backups (never consuming them) and strictly sync
    /// each destination directory, so "journal present ⇒ every journaled
    /// backup present" holds even if the machine dies mid-rollback. Every
    /// failure is reported, and on any failure the journal is REWRITTEN to
    /// exactly the pairs that still need recovery and kept: deleting it
    /// unconditionally, as this used to, left new content in place with no
    /// record of which backups hold the originals.
    pub(super) fn rollback(self) -> Recovery {
        let mut recovery = Recovery::default();
        for (dst, backup) in self.done.iter().rev() {
            match restore_from_backup(backup, dst) {
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
            // Full rollback. The journal goes FIRST, and the backups may go
            // only once its removal is DURABLE (see
            // remove_journal_then_backups).
            if !remove_journal_then_backups(&self.journal, &self.backups) {
                recovery.journal_leftover = true;
            }
        } else {
            // Partial rollback. Shrink the journal to exactly the pairs
            // still needing recovery; only once THAT is durable may the
            // other backups go — a failed rewrite keeps the old journal,
            // which still references every backup, so all of them stay.
            let rewritten =
                rewrite_journal(&self.journal, &self.worktree_root, &recovery.failed).is_ok();
            if rewritten {
                let failed: Vec<&Path> = recovery
                    .failed
                    .iter()
                    .map(|(_, backup)| backup.as_path())
                    .collect();
                delete_unreferenced_backups(
                    self.backups
                        .iter()
                        .filter(|b| !failed.contains(&b.as_path())),
                );
            }
            warn!(
                "{} file(s) could not be rolled back; the transaction journal and their \
                 backups were kept — the next git-se command will retry the restore.",
                recovery.failed.len()
            );
        }
        recovery
    }
}

/// Remove the journal and make the removal durable, then — and ONLY then —
/// delete `backups` and sync their directories away too.
///
/// Returns `false` when the journal could not be removed or its removal
/// could not be confirmed durable: the journal and ALL backups are kept,
/// because "journal present ⇒ every journaled backup present" is the
/// invariant recovery relies on. (Deleting the backups after merely warning
/// about the journal used to strand the repository in a permanent
/// missing-backup anomaly.)
fn remove_journal_then_backups(journal: &Path, backups: &[PathBuf]) -> bool {
    let parent = journal.parent().unwrap_or_else(|| Path::new("."));
    if let Err(e) = std::fs::remove_file(journal).and_then(|()| sync_dir_strict(parent)) {
        warn!(
            "Could not durably remove the transaction journal {}: {e}. The journal and all \
             backups were kept — fix the cause and re-run any git-se command, or remove that \
             journal and the {BACKUP_PREFIX}* files manually",
            journal.display()
        );
        return false;
    }
    delete_unreferenced_backups(backups.iter());
    true
}

/// Delete backups no journal references anymore (best-effort per file), then
/// strictly sync their parent directories: a power cut must not resurrect a
/// deleted backup — after an encrypt it holds plaintext. A sync failure is
/// only warned about here: the contents at the destinations are already
/// final, so a resurrected backup is garbage for the sweep, not corruption.
fn delete_unreferenced_backups<'a>(backups: impl Iterator<Item = &'a PathBuf>) {
    let mut parents: Vec<&'a Path> = Vec::new();
    for backup in backups {
        if std::fs::remove_file(backup).is_ok()
            && let Some(parent) = backup.parent()
        {
            parents.push(parent);
        }
    }
    parents.sort_unstable();
    parents.dedup();
    for parent in parents {
        if let Err(e) = sync_dir_strict(parent) {
            warn!(
                "Backups in {} were removed, but the removal could not be made durable ({e}); \
                 some may reappear after a power cut — delete them then",
                parent.display()
            );
        }
    }
}

/// Serialize a v3 journal record for `pairs`.
///
/// Paths inside `worktree_root` are recorded **relative** to it, so a
/// repository moved after a crash still recovers; anything outside keeps its
/// absolute form (a legacy journal's pairs, re-flagged during recovery).
fn build_journal_record<'a>(
    worktree_root: &Path,
    pairs: impl Iterator<Item = (&'a Path, &'a PathBuf)>,
) -> Vec<u8> {
    let mut record = Vec::new();
    record.extend_from_slice(JOURNAL_VERSION);
    record.push(0);
    for (dst, backup) in pairs {
        record.extend_from_slice(journal_path_bytes(dst, worktree_root).as_ref());
        record.push(0);
        record.extend_from_slice(journal_path_bytes(backup, worktree_root).as_ref());
        record.push(0);
    }
    record
}

/// Encode `path` for the journal: relative to `worktree_root` when inside it.
fn journal_path_bytes<'a>(path: &'a Path, worktree_root: &Path) -> std::borrow::Cow<'a, [u8]> {
    let recorded = path.strip_prefix(worktree_root).unwrap_or(path);
    path_bytes(recorded)
}

/// Rewrite the journal to exactly `pairs` (v3 format, worktree-relative
/// where possible). On failure the original journal stays, which keeps
/// recovery conservative — the caller must then keep ALL backups, since the
/// old journal still references them.
fn rewrite_journal(
    journal: &Path,
    worktree_root: &Path,
    pairs: &[(PathBuf, PathBuf)],
) -> Result<()> {
    let record = build_journal_record(worktree_root, pairs.iter().map(|(d, b)| (d.as_path(), b)));
    atomic_write_durable(journal, &record).inspect_err(|e| {
        warn!("Could not rewrite the transaction journal: {e}");
    })
}

/// Restore `dst` from `backup` by atomic COPY (temp file + fsync + rename),
/// then strictly sync the destination directory.
///
/// The backup is deliberately NOT consumed (unlike a rename): while the
/// journal exists, every backup it references keeps existing, so a crash or
/// kill mid-recovery never manufactures a missing-backup anomaly — the next
/// run just redoes the same idempotent copies.
fn restore_from_backup(backup: &Path, dst: &Path) -> std::io::Result<()> {
    copy_atomic(backup, dst)?;
    sync_dir_strict(dst.parent().unwrap_or_else(|| Path::new(".")))
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
    /// The journal exists but could not be parsed (unknown version or a
    /// truncated record). Nothing was touched and the journal is kept:
    /// guessing at a corrupt record could rename the wrong files.
    pub journal_corrupt: bool,
    /// The journal exists but could not be READ at all (permissions, a
    /// directory at that path, ...), with the OS error's message. Only
    /// `NotFound` may read as "no interrupted transaction" — folding any
    /// other read error into it used to let commands run on a
    /// half-recovered tree, and let the startup sweep delete the backups
    /// that are the last recovery material.
    pub journal_unreadable: Option<String>,
    /// Everything was restored, but the journal itself could not be removed
    /// (or its removal could not be made durable). The journal and **all**
    /// backups were kept — deleting the backups anyway would break the core
    /// invariant ("journal present ⇒ every journaled backup present") and
    /// permanently strand the repository in a missing-backup anomaly.
    pub journal_leftover: bool,
}

/// A parsed journal: the protocol version and its `(destination, backup)`
/// pairs, with every path already resolved against (and confined to) the
/// worktree being recovered.
struct ParsedJournal {
    v3: bool,
    pairs: Vec<(PathBuf, PathBuf)>,
}

/// Why a journal is rejected as corrupt.
#[derive(Debug)]
enum JournalCorrupt {
    /// A version marker this build does not know (`v9`, ...).
    UnknownVersion(Vec<u8>),
    /// A truncated record: odd field count, a missing NUL terminator, or an
    /// empty field — i.e. anything `begin` never writes.
    Truncated,
    /// A pair whose destination or backup escapes the worktree.
    OutsideWorktree(Vec<u8>),
}

/// Parse the journal strictly.
///
/// Every byte pattern `begin` can emit is accepted; anything else — an
/// unknown version, a truncated final field, an embedded empty field — is
/// corruption and must fail closed. The previous lenient parse dropped a
/// trailing odd field silently (deleting the journal as "nothing to do") and
/// interpreted an unknown version as the legacy format, pairing real paths
/// with marker bytes and renaming files out of the worktree.
///
/// Paths are resolved against `worktree_root`: relative paths (the current
/// format) join it after rejecting any component that is not a plain name;
/// absolute paths (legacy journals) must lie inside it. Either way recovery
/// can never rename a file outside the worktree being recovered.
/// `protected` carries the unified protected set (the resolved git dirs
/// plus every nested git dir discovered at open): journaled paths under
/// any of them are rejected as corruption.
fn parse_journal(
    record: &[u8],
    worktree_root: &Path,
    protected: &crate::utils::ProtectedDirs,
) -> Result<ParsedJournal, JournalCorrupt> {
    // A legal journal is a run of NUL-terminated fields, so the record must
    // end at a field boundary. An empty file is the degenerate v2 journal
    // (zero pairs) written by older versions.
    if record.is_empty() {
        return Ok(ParsedJournal {
            v3: false,
            pairs: Vec::new(),
        });
    }
    if *record.last().unwrap() != 0 {
        return Err(JournalCorrupt::Truncated);
    }
    let fields: Vec<&[u8]> = record[..record.len() - 1].split(|&b| b == 0).collect();
    if fields.iter().any(|f| f.is_empty()) {
        return Err(JournalCorrupt::Truncated);
    }

    let (v3, pair_fields) = if fields[0] == JOURNAL_VERSION {
        (true, &fields[1..])
    } else if looks_like_version_marker(fields[0]) {
        return Err(JournalCorrupt::UnknownVersion(fields[0].to_vec()));
    } else {
        (false, &fields[..])
    };
    if pair_fields.len() % 2 != 0 {
        return Err(JournalCorrupt::Truncated);
    }

    let mut pairs = Vec::with_capacity(pair_fields.len() / 2);
    for chunk in pair_fields.chunks_exact(2) {
        let dst = resolve_journal_path(chunk[0], worktree_root, protected)
            .map_err(|()| JournalCorrupt::OutsideWorktree(chunk[0].to_vec()))?;
        let backup = resolve_journal_path(chunk[1], worktree_root, protected)
            .map_err(|()| JournalCorrupt::OutsideWorktree(chunk[1].to_vec()))?;
        pairs.push((dst, backup));
    }
    Ok(ParsedJournal { v3, pairs })
}

/// Whether `field` has the shape of a version marker (`v` + digits) without
/// being a version this build knows. Legacy journals open with an absolute
/// destination path, which can never look like this.
fn looks_like_version_marker(field: &[u8]) -> bool {
    field.len() >= 2 && field[0] == b'v' && field[1..].iter().all(u8::is_ascii_digit)
}

/// Resolve one journaled path against the worktree, confining it inside.
///
/// Relative paths (current format) must consist of plain components only —
/// no `.`/`..`, roots or prefixes — and are joined to the root. Absolute
/// paths (legacy journals) are **fully** normalized lexically (`.` and `..`
/// resolved) and must then lie inside the root. Either way recovery can
/// never rename a file outside the worktree being recovered.
///
/// A plain `components().collect()` is NOT a normalization: it keeps
/// `ParentDir`, so `/repo/../victim` still passes a `starts_with("/repo")`
/// check while the filesystem resolves it to `/victim` — that once let a
/// crafted legacy journal overwrite a file outside the repository.
fn resolve_journal_path(
    field: &[u8],
    worktree_root: &Path,
    protected: &crate::utils::ProtectedDirs,
) -> Result<PathBuf, ()> {
    use std::path::Component;
    let raw = bytes_path(field);
    let normalized = if raw.is_absolute() {
        normalize_lexically(&raw).ok_or(())?
    } else {
        // Relative paths are never given the benefit of `..` resolution:
        // `begin` only ever writes plain components.
        if !raw.components().all(|c| matches!(c, Component::Normal(_))) {
            return Err(());
        }
        worktree_root.join(&raw)
    };
    let Ok(relative) = normalized.strip_prefix(worktree_root) else {
        return Err(());
    };
    // Git internals and the git-se config can never be a genuine recovery
    // target: no transaction touches them, so a journal naming them is
    // corrupt (or hostile) and must not be acted on. (Only the ROOT config
    // file is protected; a same-named file in a subdirectory is ordinary
    // content — and a backup never equals either.) `protected` is the
    // unified set: the RESOLVED git dirs (a `--separate-git-dir` layout can
    // place them inside the worktree under a name that need not be `.git`)
    // plus every nested git dir discovered at open — a journal left behind
    // by a vulnerable version, or a hostile one, must never restore INTO a
    // nested repository either (2026-07 audit).
    if crate::utils::has_git_component(relative)
        || protected.contains_rel(relative)
        || relative == Path::new(crate::config::CONFIG_FILE_NAME)
    {
        return Err(());
    }
    // The lexical check alone is not enough: `repo/link -> /outside` makes
    // `repo/link/victim` pass it while every write lands outside the
    // worktree. Same rule as for ordinary targets — refuse any symlinked
    // component inside the repository. (The remaining swap-after-check
    // window is the documented TOCTOU limit.)
    if crate::utils::reject_symlinked_components(&normalized, worktree_root, worktree_root).is_err()
    {
        return Err(());
    }
    Ok(normalized)
}

/// Lexically normalize a path, resolving `.` and `..` against the preceding
/// components (shared with the nested-gitdir-pointer resolution).
use crate::utils::normalize_lexically;

/// Roll back an interrupted commit phase, if one is recorded.
///
/// Called when a repository is opened, with the worktree root the journal's
/// relative paths resolve against and the unified protected set (resolved
/// git dirs plus nested discoveries) that journaled paths are confined
/// against. Returning the repository to its pre-operation state is always
/// safe: every operation here is idempotent, so the user simply re-runs
/// the command.
///
/// Every restore failure is reported loudly, and the journal is removed only
/// when everything restorable was restored — deleting it unconditionally, as
/// this used to, threw away the record of what still needed manual recovery
/// (and the sweep then deleted the backups too). A PARTIAL recovery rewrites
/// the journal to exactly the pairs still needing it: pairs whose backup was
/// consumed by a successful restore must leave the journal, or the next run
/// re-flags them as missing-backup anomalies and the journal can never
/// clear.
#[must_use]
pub fn recover(
    git_dir: &Path,
    worktree_root: &Path,
    protected: &crate::utils::ProtectedDirs,
) -> Recovery {
    let journal = git_dir.join(JOURNAL_NAME);
    let record = match std::fs::read(&journal) {
        Ok(record) => record,
        // Only a genuinely ABSENT journal is the common "no interrupted
        // transaction" case. Anything else — permissions, a directory at
        // that path, other I/O failures — must fail closed.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Recovery::default(),
        Err(e) => {
            warn!(
                "The transaction journal at {} exists but could not be read: {e}. Nothing was \
                 restored; fix the cause and re-run any git-se command to retry recovery.",
                journal.display()
            );
            return Recovery {
                journal_unreadable: Some(e.to_string()),
                ..Recovery::default()
            };
        }
    };

    let parsed = match parse_journal(&record, worktree_root, protected) {
        Ok(parsed) => parsed,
        Err(corrupt) => {
            let detail = match &corrupt {
                JournalCorrupt::UnknownVersion(v) => {
                    format!("unknown version marker {:?}", String::from_utf8_lossy(v))
                }
                JournalCorrupt::Truncated => "a truncated or malformed record".to_string(),
                JournalCorrupt::OutsideWorktree(p) => format!(
                    "a path outside the worktree: {:?}",
                    String::from_utf8_lossy(p)
                ),
            };
            warn!(
                "The transaction journal at {} is corrupt ({detail}); nothing was restored and \
                 the journal is kept. Inspect it manually, restore any unrestored destinations \
                 from their backups, then remove the journal.",
                journal.display()
            );
            return Recovery {
                journal_corrupt: true,
                ..Recovery::default()
            };
        }
    };
    let v3 = parsed.v3;
    // v2 semantics take a missing backup to mean "never replaced" — but that
    // only holds when the missing backups form a contiguous SUFFIX: the old
    // protocol backed up files in order during the commit, so a crash can
    // only truncate the tail. A missing backup with a PRESENT one after it
    // is impossible that way and means something else ate the backup (the
    // destination may already hold new content) — fail closed on it.
    let v2_gap = !v3 && {
        let first_missing = parsed.pairs.iter().position(|(_, b)| !b.exists());
        first_missing.is_some_and(|i| parsed.pairs[i..].iter().any(|(_, b)| b.exists()))
    };
    let mut recovery = Recovery::default();
    for (dst, backup) in &parsed.pairs {
        if !backup.exists() {
            if v3 || v2_gap {
                warn!(
                    "The transaction journal references a backup that no longer exists: {}. \
                     {} may already hold new content — verify it manually. The journal is \
                     kept for manual recovery.",
                    backup.display(),
                    dst.display()
                );
                recovery.failed.push((dst.clone(), backup.clone()));
            }
            continue;
        }
        // COPY the backup back (it stays in place — see restore_from_backup)
        // and strictly sync the destination directory before the journal
        // below is touched.
        match restore_from_backup(backup, dst) {
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
    if recovery.restored > 0 {
        warn!(
            "A previous git-se run was interrupted while replacing files; {} file(s) were \
             restored to their pre-run content. Re-run the command to finish.",
            recovery.restored
        );
    }
    conclude_recovery(&journal, worktree_root, &parsed.pairs, &mut recovery);
    recovery
}

/// Wind a recovery down: move the journal on (delete it when nothing is
/// left, shrink it to the failed pairs otherwise), then collect the backups
/// nothing references anymore.
///
/// Backups go ONLY after the journal does: while a journal exists, every
/// backup it references must exist too. A failed journal rewrite therefore
/// keeps every backup (the old journal still points at all of them), and a
/// re-run simply redoes the same idempotent copies.
fn conclude_recovery(
    journal: &Path,
    worktree_root: &Path,
    pairs: &[(PathBuf, PathBuf)],
    recovery: &mut Recovery,
) {
    if recovery.failed.is_empty() {
        // Full recovery: restoring copied the backups, so they must be
        // removed explicitly — but only once the journal's removal is
        // durable (see remove_journal_then_backups).
        let backups: Vec<PathBuf> = pairs.iter().map(|(_, b)| b.clone()).collect();
        if !remove_journal_then_backups(journal, &backups) {
            recovery.journal_leftover = true;
        }
        return;
    }
    // Keep exactly the pairs still needing recovery; only once THAT is
    // durable may the restored pairs' backups go.
    let rewritten = rewrite_journal(journal, worktree_root, &recovery.failed).is_ok();
    if rewritten {
        let failed: Vec<&Path> = recovery
            .failed
            .iter()
            .map(|(_, backup)| backup.as_path())
            .collect();
        delete_unreferenced_backups(
            pairs
                .iter()
                .map(|(_, backup)| backup)
                .filter(|b| !failed.contains(&b.as_path())),
        );
    }
    warn!(
        "{} file(s) could not be restored; keeping the transaction journal and the \
         remaining backups for manual recovery.",
        recovery.failed.len()
    );
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
        // `strong_count`, NOT `upgrade().is_some()`: upgrading inside the
        // mutex creates a temporary Arc that, if it turns out to be the last
        // strong reference, is destroyed while the mutex is still held —
        // and RepoLock::drop (this code) would try to lock that same mutex:
        // a self-deadlock.
        if let Some(registry) = HELD_LOCKS.get() {
            registry
                .lock()
                .retain(|(path, weak)| path != &self.path && weak.strong_count() > 0);
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
    let registry = HELD_LOCKS.get_or_init(|| Mutex::new(Vec::new()));
    // The whole check-and-acquire runs under the registry mutex: releasing
    // it between "no handle registered" and "file locked + registered" used
    // to let two threads of THIS process race — both missed the registry,
    // and the loser of `try_lock` got a spurious `RepoLocked` instead of a
    // shared handle. `try_lock` is non-blocking, so holding the mutex across
    // it costs nothing; cross-process exclusion still comes from the flock
    // itself.
    let mut held = registry.lock();
    // `strong_count`, not `upgrade().is_some()` — see RepoLock::drop for the
    // self-deadlock an upgraded-then-dropped temporary Arc could cause while
    // this mutex is held. (The upgrade below is fine: its Arc is returned to
    // the caller and outlives the mutex.)
    held.retain(|(_, weak)| weak.strong_count() > 0);
    if let Some(lock) = held
        .iter()
        .find(|(path, _)| path == &lock_path)
        .and_then(|(_, weak)| weak.upgrade())
    {
        return Ok(Some(lock));
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
            held.push((lock_path, Arc::downgrade(&lock)));
            drop(held);
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
    // Preserve permissions AND timestamps, so a rollback on a filesystem
    // without hard links restores the metadata too — a bare
    // `set_permissions` used to reset the mtime to backup time, breaking the
    // "permissions and timestamps preserved" guarantee. (Ownership and
    // xattrs are out of scope: they need privileges no ordinary run has.)
    if let Err(e) = copy_metadata::copy_metadata(src, temp.path()) {
        warn!(
            "Could not copy metadata from {} to its backup: {e}",
            src.display()
        );
    }
    // The metadata writes above dirty the inode after the first sync; flush
    // again so the backup is durable in its final state.
    temp.as_file().sync_all()?;
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
    use crate::{
        crypt::header::SALT_LEN,
        utils::{ProtectedDirs, atomic_write},
    };

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

        let recovery = recover(&git_dir, root, &ProtectedDirs::default());
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

        let recovery = recover(&git_dir, root, &ProtectedDirs::default());
        assert_eq!(recovery.restored, 0);
        assert_eq!(recovery.failed, vec![(dst, backup.clone())]);
        assert!(
            git_dir.join(JOURNAL_NAME).exists(),
            "the journal must survive a failed recovery"
        );
        assert!(backup.exists(), "the backup must survive a failed recovery");
    }

    /// v2 (legacy) semantics: missing backups forming a contiguous SUFFIX
    /// simply mean "never replaced" (the old protocol backed up in order),
    /// so they are skipped — the files keep their current content.
    #[test]
    fn test_recover_v2_skips_missing_backup() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path();
        let git_dir = root.join(".git");

        let a = write_file(root, "a", b"NEW0");
        let b = write_file(root, "b", b"NEW1");
        let bak_a = write_file(root, ".git-se-bak.33333333.0", b"OLD0");
        craft_journal_v2(
            &git_dir,
            &[(&a, &bak_a), (&b, &root.join(".git-se-bak.33333333.1"))],
        );

        let recovery = recover(&git_dir, root, &ProtectedDirs::default());
        assert_eq!(recovery.restored, 1);
        assert!(recovery.failed.is_empty());
        assert_eq!(std::fs::read(&a).unwrap(), b"OLD0");
        assert_eq!(std::fs::read(&b).unwrap(), b"NEW1");
        assert!(!git_dir.join(JOURNAL_NAME).exists());
    }

    /// v2 semantics, anomaly: a missing backup with a PRESENT one after it
    /// cannot come from the old in-order protocol — something else ate it,
    /// and the destination may already hold new content. Fail closed on the
    /// missing pair (the present one is still restored: its original is
    /// known), keep the journal for manual verification.
    #[test]
    fn test_recover_v2_missing_backup_gap_fails_closed() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path();
        let git_dir = root.join(".git");

        let a = write_file(root, "a", b"NEW0");
        let b = write_file(root, "b", b"NEW1");
        let bak_b = write_file(root, ".git-se-bak.33333334.1", b"OLD1");
        craft_journal_v2(
            &git_dir,
            &[(&a, &root.join(".git-se-bak.33333334.0")), (&b, &bak_b)],
        );

        let recovery = recover(&git_dir, root, &ProtectedDirs::default());
        // The present backup IS restored (that file's original is known)...
        assert_eq!(recovery.restored, 1);
        assert_eq!(std::fs::read(&b).unwrap(), b"OLD1");
        // ...but the gapped missing one is an anomaly: reported, untouched,
        // and the journal stays for manual recovery.
        assert_eq!(recovery.failed.len(), 1);
        assert_eq!(std::fs::read(&a).unwrap(), b"NEW0");
        assert!(git_dir.join(JOURNAL_NAME).exists());
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

        let recovery = recover(&git_dir, root, &ProtectedDirs::default());
        // The present backup IS restored (that file's original is known)...
        assert_eq!(std::fs::read(&b).unwrap(), b"OLD1");
        // ...but the missing one is an anomaly: reported, untouched, and the
        // journal stays for manual recovery.
        assert_eq!(recovery.restored, 1);
        assert_eq!(recovery.failed.len(), 1);
        assert_eq!(std::fs::read(&a).unwrap(), b"NEW0");
        assert!(git_dir.join(JOURNAL_NAME).exists());
    }

    /// A PARTIAL recovery must rewrite the journal to the pairs still
    /// needing it: a restored pair's backup is consumed by the rename, and
    /// leaving the pair in the journal re-flags it as a missing-backup
    /// anomaly on the next run — the journal could never clear.
    #[test]
    fn test_recover_partial_rewrites_journal_and_converges() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path();
        let git_dir = root.join(".git");

        let a = write_file(root, "a", b"NEW_A");
        let bak_a = write_file(
            root,
            ".git-se-bak.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.0",
            b"OLD_A",
        );
        // b's restore fails: a non-empty directory sits at its destination.
        let b = root.join("b");
        std::fs::create_dir(&b).unwrap();
        std::fs::write(b.join("occupied"), b"x").unwrap();
        let bak_b = write_file(
            root,
            ".git-se-bak.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.1",
            b"OLD_B",
        );
        craft_journal_v3(&git_dir, &[(&a, &bak_a), (&b, &bak_b)]);

        // First pass: a restores, b fails; the journal must shrink to ONLY
        // b's pair, and a's backup — no longer referenced — is collected.
        let recovery = recover(&git_dir, root, &ProtectedDirs::default());
        assert_eq!(recovery.restored, 1);
        assert_eq!(recovery.failed, vec![(b.clone(), bak_b.clone())]);
        let record = std::fs::read(git_dir.join(JOURNAL_NAME)).unwrap();
        let parsed = parse_journal(&record, root, &ProtectedDirs::default()).unwrap();
        assert_eq!(parsed.pairs, vec![(b.clone(), bak_b)]);
        assert!(
            !bak_a.exists(),
            "a restored pair's backup must be collected once the rewritten journal is durable"
        );

        // The obstruction is removed; the second pass finishes the job and
        // clears the journal — converged, no permanent anomaly.
        std::fs::remove_dir_all(&b).unwrap();
        let recovery = recover(&git_dir, root, &ProtectedDirs::default());
        assert_eq!(recovery.restored, 1);
        assert!(recovery.failed.is_empty());
        assert_eq!(std::fs::read(&a).unwrap(), b"OLD_A");
        assert_eq!(std::fs::read(&b).unwrap(), b"OLD_B");
        assert!(!git_dir.join(JOURNAL_NAME).exists());
    }

    /// A truncated v3 journal (odd field count) is corruption: nothing is
    /// touched and the journal is kept — it used to be silently deleted.
    #[test]
    fn test_recover_truncated_journal_fails_closed() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path();
        let git_dir = root.join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();
        let journal = git_dir.join(JOURNAL_NAME);

        // v3 marker + a destination without its backup field.
        let mut record = b"v3\0".to_vec();
        record.extend_from_slice(b"a");
        record.push(0);
        atomic_write(&journal, &record).unwrap();

        let recovery = recover(&git_dir, root, &ProtectedDirs::default());
        assert!(recovery.journal_corrupt);
        assert_eq!(recovery.restored, 0);
        assert!(recovery.failed.is_empty());
        assert!(journal.exists(), "a corrupt journal must be kept");

        // Missing NUL terminator on the last field is also truncation.
        std::fs::write(&journal, b"v3\0a\0b").unwrap();
        let recovery = recover(&git_dir, root, &ProtectedDirs::default());
        assert!(recovery.journal_corrupt);
        assert!(journal.exists());

        // An embedded empty field (a double NUL) used to be filtered out,
        // silently shifting every pair after it.
        std::fs::write(&journal, b"v3\0\0a\0b\0").unwrap();
        let recovery = recover(&git_dir, root, &ProtectedDirs::default());
        assert!(recovery.journal_corrupt);
        assert!(journal.exists());
    }

    /// An unknown version marker must fail closed: the old parse treated it
    /// as the legacy format, pairing the MARKER with real paths and renaming
    /// a real file out of the worktree.
    #[test]
    fn test_recover_unknown_version_fails_closed() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path();
        let git_dir = root.join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();
        let journal = git_dir.join(JOURNAL_NAME);

        let dst = write_file(root, "f", b"NEW");
        let backup = write_file(
            root,
            ".git-se-bak.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.0",
            b"OLD",
        );
        let mut record = b"v9\0".to_vec();
        record.extend_from_slice(path_bytes(&dst).as_ref());
        record.push(0);
        record.extend_from_slice(path_bytes(&backup).as_ref());
        record.push(0);
        atomic_write(&journal, &record).unwrap();

        let recovery = recover(&git_dir, root, &ProtectedDirs::default());
        assert!(recovery.journal_corrupt);
        assert_eq!(std::fs::read(&dst).unwrap(), b"NEW");
        assert!(backup.exists());
        assert!(journal.exists());
    }

    /// A journaled path outside the worktree (hand-edited or a moved
    /// repository's legacy absolute journal) must never be renamed into.
    #[test]
    fn test_recover_rejects_paths_outside_worktree() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path();
        let git_dir = root.join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();
        let journal = git_dir.join(JOURNAL_NAME);

        let outside = tempfile::TempDir::new().unwrap();
        let dst = outside.path().join("f");
        let backup = outside.path().join(".git-se-bak.0");
        std::fs::write(&dst, b"NEW").unwrap();
        std::fs::write(&backup, b"OLD").unwrap();
        craft_journal_v3(&git_dir, &[(&dst, &backup)]);

        let recovery = recover(&git_dir, root, &ProtectedDirs::default());
        assert!(recovery.journal_corrupt);
        assert_eq!(std::fs::read(&dst).unwrap(), b"NEW");
        assert!(journal.exists());

        // A relative path with a `..` component is likewise refused.
        let mut record = b"v3\0".to_vec();
        record.extend_from_slice(b"../escape");
        record.push(0);
        record.extend_from_slice(b"sub/.git-se-bak.0");
        record.push(0);
        atomic_write(&journal, &record).unwrap();
        let recovery = recover(&git_dir, root, &ProtectedDirs::default());
        assert!(recovery.journal_corrupt);
        assert!(journal.exists());
    }

    /// While the journal cannot be durably removed, NO backup may go:
    /// deleting them anyway used to break "journal present ⇒ every journaled
    /// backup present" and permanently strand the repository in a
    /// missing-backup anomaly.
    #[test]
    fn test_conclude_recovery_keeps_backups_when_journal_stuck() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path();
        let git_dir = root.join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();

        let a = write_file(root, "a", b"OLD");
        let bak = write_file(root, ".git-se-bak.aa.0", b"OLD");
        let pairs = vec![(a, bak.clone())];

        // A directory at the journal's path makes remove_file fail (EISDIR).
        let journal = git_dir.join(JOURNAL_NAME);
        std::fs::create_dir(&journal).unwrap();

        let mut recovery = Recovery {
            restored: 1,
            ..Recovery::default()
        };
        conclude_recovery(&journal, root, &pairs, &mut recovery);
        assert!(recovery.journal_leftover);
        assert!(
            bak.exists(),
            "the backup must survive while the journal survives"
        );

        // The happy path removes both journal and backups.
        std::fs::remove_dir(&journal).unwrap();
        atomic_write(&journal, b"v3\0").unwrap();
        let mut recovery = Recovery {
            restored: 1,
            ..Recovery::default()
        };
        conclude_recovery(&journal, root, &pairs, &mut recovery);
        assert!(!recovery.journal_leftover);
        assert!(!journal.exists());
        assert!(!bak.exists());
    }

    /// A journaled path that passes the lexical check but resolves through
    /// a SYMLINK out of the worktree (`repo/link -> /outside`) must be
    /// refused: restoring used to write the backup content outside the repo.
    #[cfg(unix)]
    #[test]
    fn test_recover_rejects_symlinked_components() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().join("repo");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();

        let backup = root.join(".git-se-bak.aa.0");
        std::fs::write(&backup, b"BACKUP").unwrap();
        craft_journal_v3(&root.join(".git"), &[(&root.join("link/victim"), &backup)]);

        let recovery = recover(&root.join(".git"), &root, &ProtectedDirs::default());
        assert!(recovery.journal_corrupt);
        assert!(
            !outside.join("victim").exists(),
            "recovery must never write through a symlink out of the worktree"
        );
        assert!(backup.exists());
    }

    /// An absolute legacy path like `<root>/../victim` lexically STARTS with
    /// the worktree but resolves OUTSIDE it. `components().collect()` keeps
    /// the `..` and used to wave it through `starts_with` — overwriting a
    /// file outside the repository. Full lexical normalization must reject it.
    #[test]
    fn test_recover_rejects_dotdot_absolute_path() {
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path();
        let root = base.join("repo");
        let git_dir = root.join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();

        let victim = base.join("victim");
        std::fs::write(&victim, b"ORIGINAL").unwrap();
        let backup = root.join(".git-se-bak.0");
        std::fs::write(&backup, b"BACKUP_CONTENT").unwrap();

        // v2 journal whose destination is `<root>/../victim`.
        let mut record = Vec::new();
        record.extend_from_slice(path_bytes(&root.join("../victim")).as_ref());
        record.push(0);
        record.extend_from_slice(path_bytes(&backup).as_ref());
        record.push(0);
        atomic_write(&git_dir.join(JOURNAL_NAME), &record).unwrap();

        let recovery = recover(&git_dir, &root, &ProtectedDirs::default());
        assert!(recovery.journal_corrupt);
        assert_eq!(std::fs::read(&victim).unwrap(), b"ORIGINAL");
        assert!(backup.exists());

        // Unit-level: normalization resolves `..` BEFORE the prefix check.
        let root_path = root.as_path();
        assert!(
            resolve_journal_path(
                path_bytes(&root.join("a")).as_ref(),
                root_path,
                &ProtectedDirs::default()
            )
            .is_ok()
        );
        assert!(
            resolve_journal_path(
                path_bytes(&root.join("../victim")).as_ref(),
                root_path,
                &ProtectedDirs::default()
            )
            .is_err(),
            "an absolute path escaping via `..` must be rejected"
        );
        assert!(
            resolve_journal_path(
                path_bytes(&root.join("sub/../a")).as_ref(),
                root_path,
                &ProtectedDirs::default()
            )
            .is_ok_and(|p| p == root.join("a")),
            "`..` that stays inside the worktree must resolve, not just be allowed"
        );
        // `.git` internals and the git-se config are never recovery targets.
        assert!(
            resolve_journal_path(
                path_bytes(&root.join(".git/config")).as_ref(),
                root_path,
                &ProtectedDirs::default()
            )
            .is_err()
        );
        assert!(
            resolve_journal_path(
                path_bytes(&root.join(crate::config::CONFIG_FILE_NAME)).as_ref(),
                root_path,
                &ProtectedDirs::default()
            )
            .is_err()
        );
    }

    /// Regression (2026-07 audit): with the git dir INSIDE the worktree (a
    /// `--separate-git-dir` layout, here `meta/`), a journal naming a path
    /// under it must be rejected as corrupt — recovery must never write
    /// into git internals, however they are named. The protected set is
    /// built exactly as `Repo::open` builds it.
    #[test]
    fn test_recover_rejects_paths_inside_resolved_git_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().join("repo");
        let git_dir = root.join("meta"); // separate-git-dir layout
        std::fs::create_dir_all(&git_dir).unwrap();
        let journal = git_dir.join(JOURNAL_NAME);
        let protected = ProtectedDirs::new(vec![git_dir.clone()], &root);

        let dst = git_dir.join("HEAD");
        std::fs::write(&dst, b"ref: refs/heads/main").unwrap();
        let backup = root.join(".git-se-bak.cccccccccccccccccccccccccccccccc.0");
        std::fs::write(&backup, b"BACKUP").unwrap();
        craft_journal_v3(&git_dir, &[(&dst, &backup)]);

        let recovery = recover(&git_dir, &root, &protected);
        assert!(
            recovery.journal_corrupt,
            "a journal naming git internals must be rejected as corrupt"
        );
        assert_eq!(std::fs::read(&dst).unwrap(), b"ref: refs/heads/main");
        assert!(backup.exists(), "a rejected pair's backup must be kept");
        assert!(journal.exists(), "a corrupt journal must be kept");
    }

    /// Regression (2026-07 audit): the unified protected set — including a
    /// NESTED git dir discovered at open, not just the journal's own —
    /// confines recovery. A journal left by a vulnerable version (or a
    /// hostile one) naming a path inside the nested dir must be rejected
    /// as corrupt, never restored into.
    #[test]
    fn test_recover_rejects_paths_inside_nested_protected_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().join("repo");
        let git_dir = root.join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();
        let journal = git_dir.join(JOURNAL_NAME);
        // A nested repository as discovered at open (bare repo, separate
        // git dir, ...): part of the protected set.
        let nested = root.join("bare-repo");
        std::fs::create_dir_all(&nested).unwrap();
        let protected = ProtectedDirs::new(vec![git_dir.clone(), nested.clone()], &root);

        let dst = nested.join("HEAD");
        std::fs::write(&dst, b"ref: refs/heads/main").unwrap();
        let backup = root.join(".git-se-bak.dddddddddddddddddddddddddddddddd.0");
        std::fs::write(&backup, b"BACKUP").unwrap();
        craft_journal_v3(&git_dir, &[(&dst, &backup)]);

        let recovery = recover(&git_dir, &root, &protected);
        assert!(
            recovery.journal_corrupt,
            "a journal naming a nested git dir must be rejected as corrupt"
        );
        assert_eq!(std::fs::read(&dst).unwrap(), b"ref: refs/heads/main");
        assert!(backup.exists(), "a rejected pair's backup must be kept");
        assert!(journal.exists(), "a corrupt journal must be kept");
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

        let mut txn = Transaction::begin(&git_dir, root, &writes).unwrap();
        // All backups exist already, and the journal is v3-versioned.
        assert_eq!(txn.backups.len(), 2);
        for backup in &txn.backups {
            assert!(backup.exists());
        }
        let journal = std::fs::read(git_dir.join(JOURNAL_NAME)).unwrap();
        assert!(journal.starts_with(b"v3\0"));
        // Paths are recorded RELATIVE to the worktree, so a repository moved
        // after a crash still recovers.
        let parsed = parse_journal(&journal, root, &ProtectedDirs::default()).unwrap();
        assert_eq!(
            parsed.pairs,
            vec![
                (a.clone(), txn.backups[0].clone()),
                (b.clone(), txn.backups[1].clone())
            ]
        );

        for (index, write) in writes.into_iter().enumerate() {
            txn.commit_one(index, write).unwrap();
        }
        assert_eq!(std::fs::read(&a).unwrap(), b"NEW_A");
        assert_eq!(std::fs::read(&b).unwrap(), b"NEW_B");

        let unremoved = txn.finish().unwrap();
        assert!(unremoved.is_empty());
        assert!(!git_dir.join(JOURNAL_NAME).exists());
        assert!(std::fs::read_dir(root).unwrap().all(|e| {
            !e.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(BACKUP_PREFIX)
        }));
    }

    /// A backup that cannot be removed after a successful commit must be
    /// REPORTED (after an encrypt it holds plaintext) — the error used to be
    /// swallowed and the plaintext left behind silently.
    #[test]
    fn test_finish_reports_unremovable_backup() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path();
        let git_dir = root.join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();

        let a = write_file(root, "a", b"OLD_A");
        let writes = vec![prepared_write(root, &a, b"NEW_A")];
        let mut txn = Transaction::begin(&git_dir, root, &writes).unwrap();
        txn.commit_one(0, writes.into_iter().next().unwrap())
            .unwrap();

        // Make the backup unremovable: replace it with a non-empty
        // directory at the same path.
        let backup = txn.backups[0].clone();
        std::fs::remove_file(&backup).unwrap();
        std::fs::create_dir(&backup).unwrap();
        std::fs::write(backup.join("occupied"), b"x").unwrap();

        let unremoved = txn.finish().unwrap();
        assert_eq!(unremoved, vec![backup.clone()]);
        assert!(!git_dir.join(JOURNAL_NAME).exists());
        std::fs::remove_dir_all(&backup).unwrap();
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
        let mut txn = Transaction::begin(&git_dir, root, &writes).unwrap();
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
        let mut txn = Transaction::begin(&git_dir, root, &writes).unwrap();
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
        let recovery = recover(&git_dir, root, &ProtectedDirs::default());
        assert_eq!(recovery.restored, 1);
        assert!(recovery.failed.is_empty());
        assert_eq!(std::fs::read(&a).unwrap(), b"OLD_A");
        assert!(!git_dir.join(JOURNAL_NAME).exists());
    }

    /// Regression (2026-07 audit): a journal that exists but cannot be READ
    /// is NOT "no transaction" — only `NotFound` may produce the default
    /// recovery. Folding other read errors into it let commands run on a
    /// half-recovered tree and let the sweep delete the backups.
    #[test]
    fn test_recover_unreadable_journal_fails_closed() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path();
        let git_dir = root.join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();
        // A directory at the journal's path makes `fs::read` fail (EISDIR).
        let journal = git_dir.join(JOURNAL_NAME);
        std::fs::create_dir(&journal).unwrap();

        let recovery = recover(&git_dir, root, &ProtectedDirs::default());
        assert!(
            recovery.journal_unreadable.is_some(),
            "an unreadable journal must be flagged, got {recovery:?}"
        );
        assert_eq!(recovery.restored, 0);
        assert!(journal.is_dir(), "the unreadable journal must be kept");
    }

    /// `begin` must refuse to start when ANY entry occupies the journal
    /// path — including a dangling symlink, which `exists()` reports as
    /// absent while a new journal would silently replace the name.
    #[cfg(unix)]
    #[test]
    fn test_begin_refuses_dangling_symlink_at_journal_path() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path();
        let git_dir = root.join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();
        std::os::unix::fs::symlink("/nonexistent-target", git_dir.join(JOURNAL_NAME)).unwrap();
        assert!(
            !git_dir.join(JOURNAL_NAME).exists(),
            "setup: the symlink dangles"
        );

        let a = write_file(root, "a", b"OLD_A");
        let writes = vec![prepared_write(root, &a, b"NEW_A")];
        assert!(
            Transaction::begin(&git_dir, root, &writes).is_err(),
            "an occupied journal path must refuse a new transaction"
        );
        // The failed begin must not have created backups of anything.
        assert!(std::fs::read_dir(root).unwrap().all(|e| {
            !e.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(BACKUP_PREFIX)
        }));
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
        assert!(Transaction::begin(&git_dir, root, &writes).is_err());
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
