//! Persistent `salt+file_id` cache for deterministic re-encryption.
//!
//! During **decrypt**, the file's salt and `file_id` are recorded. During
//! **encrypt**, the cached values are reused so that decrypt→encrypt on the
//! same plaintext produces byte-identical output.
//!
//! # Architecture
//!
//! ## Read Path (encrypt) — owned map via rkyv
//!
//! [`SaltCacheReader`] reads the cache file and deserializes it into an
//! owned `HashMap<Vec<u8>, CachedEntry>` via rkyv's safe API. The cache is
//! small (32 bytes per file plus the path), so an owned map is cheap — and
//! unlike the previous mmap + `access_unchecked` design it carries no
//! unsafe aliasing contract if another process rewrites the file.
//!
//! ## Write Path (decrypt) — mpsc + rkyv
//!
//! [`SaltCacheSender`] is a `Sync` handle that wraps an `mpsc::Sender`.
//! Rayon worker threads send `(path, entry)` pairs through the channel.
//! After all parallel work completes, [`SaltCacheSaver`] collects the
//! entries, merges with any existing on-disk cache, and serializes the
//! result via rkyv.
//!
//! ## Cross-process locking
//!
//! All file access (read-merge-write on save, read on load) is guarded by an
//! advisory [`fd_lock`] on a sibling lockfile, so two concurrently running
//! `git-se` processes cannot lose each other's newly written entries
//! (last-writer-wins would silently drop entries written by the loser). The
//! lock is **fail-closed**: an operation that cannot take it reports an
//! error rather than silently risking that guarantee.
//!
//! # Key Format
//!
//! Cache keys are repo-relative path bytes with forward slashes (`b'/'`),
//! computed by the caller via [`crate::crypt::cache_key`]. Using raw bytes
//! (`Vec<u8>`) avoids UTF-8 validation overhead and string allocation.
//!
//! # Persistence
//!
//! Serialized via [`rkyv`] to `<git-dir>/git-simple-encrypt-salt-cache`, where
//! `<git-dir>` is the per-worktree git dir (`git rev-parse
//! --absolute-git-dir`), so linked worktrees and submodules get their own
//! cache. The binary format is opaque and not meant for human consumption.
//! Writes are performed atomically to prevent corruption.
//!
//! # Lifecycle
//!
//! - **Decrypt**: Create sender → workers send entries → saver persists
//!   (atomically)
//! - **Encrypt**: Create reader (owned map, read-only) → workers look up
//!   cached values. **No write** is performed during encryption.
//! - **On error**: Cache is saved with whatever entries were captured before
//!   the failure, preserving partial progress.
//! - **Stale entries**: Entries for files that no longer exist are harmless
//!   (looked up by key, simply not found) and do not affect correctness.

use std::{
    collections::HashMap,
    fmt,
    path::{Path, PathBuf},
    sync::mpsc,
};

use log::{debug, warn};
use rkyv::rancor::Error as RkyvError;

use crate::{
    crypt::{FILE_ID_LEN, SALT_LEN},
    utils::atomic_write,
};

/// File name for the persistent salt cache, stored inside the git dir.
const CACHE_FILENAME: &str = "git-simple-encrypt-salt-cache";
/// Advisory lockfile guarding cross-process cache reads and writes.
const LOCK_FILENAME: &str = "git-simple-encrypt-salt-cache.lock";

/// A cached header entry for deterministic re-encryption.
///
/// Stores the salt (for key derivation) and `file_id` (for nonce derivation) so
/// that re-encrypting the same plaintext produces byte-identical ciphertext.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct CachedEntry {
    pub salt: [u8; SALT_LEN],
    pub file_id: [u8; FILE_ID_LEN],
}

/// Borrowed reference to a salt-cache writer + the repo-relative key for a
/// single file.
///
/// Passed into [`crate::crypt::decrypt_file_with_cache`] so that the decrypt
/// path can record `(salt, file_id)` for deterministic re-encryption.
#[derive(Clone, Copy)]
pub struct CacheRef<'a> {
    /// The thread-safe sender that forwards entries to the persister thread.
    pub sender: &'a SaltCacheSender,
    /// Forward-slash-normalized repo-relative path bytes for this file.
    pub key: &'a [u8],
}

impl fmt::Debug for CacheRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CacheRef")
            .field("sender", &"SaltCacheSender")
            .field("key", &String::from_utf8_lossy(self.key))
            .finish()
    }
}

/// Returns the cache file path for the given git dir (see
/// [`crate::repo::Repo::git_dir`]).
fn cache_path(git_dir: &Path) -> PathBuf {
    git_dir.join(CACHE_FILENAME)
}

/// Advisory cross-process lock for the cache (readers take read locks,
/// writers take write locks). Fail-closed by design: the read-merge-write
/// cycle only keeps its "no lost entries" guarantee while the lock is held,
/// and the repository lock (`git-se.lock`, same directory, mandatory) already
/// proves the git dir is writable — so a failure here is an anomaly to
/// report, not a condition to work around. The `try_` variants are used so a
/// stuck foreign holder surfaces as an error instead of a silent hang.
///
/// `pub(crate)` for tests that simulate a foreign lock holder.
pub(crate) fn open_cache_lock(
    git_dir: &Path,
) -> crate::error::Result<fd_lock::RwLock<std::fs::File>> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(git_dir.join(LOCK_FILENAME))?;
    Ok(fd_lock::RwLock::new(file))
}

/// Read the cache file and deserialize it, under a shared lock. `None` when
/// missing or corrupted (a fresh start is not an error). Fails when the
/// guarding lock cannot be taken.
fn read_cache_map(git_dir: &Path) -> crate::error::Result<Option<HashMap<Vec<u8>, CachedEntry>>> {
    let path = cache_path(git_dir);
    // The lock comes FIRST: "the cache does not exist" is a fact that must
    // be established under the lock, or a writer holding it could be midway
    // through creating the file and this read would skip the very entries
    // being written (2026-07 audit). When the git dir itself is absent
    // (plain directory), no writer can exist either — the lock cannot be
    // taken and is meaningless there.
    if !git_dir.is_dir() {
        debug!(
            "git dir {} does not exist; treating the salt cache as empty",
            git_dir.display()
        );
        return Ok(None);
    }
    let lock = open_cache_lock(git_dir)?;
    let _guard = lock.try_read().map_err(|e| {
        crate::error::Error::SaltCache(format!(
            "could not lock {} for reading: {e}",
            git_dir.join(LOCK_FILENAME).display()
        ))
    })?;
    if !path.exists() {
        debug!("Salt cache not found at {}", path.display());
        return Ok(None);
    }
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            warn!("Failed to read salt cache at {}: {e}", path.display());
            return Ok(None);
        }
    };
    match rkyv::from_bytes::<HashMap<Vec<u8>, CachedEntry>, RkyvError>(&bytes) {
        Ok(map) => {
            debug!(
                "Loaded salt cache ({} entries) from {}",
                map.len(),
                path.display()
            );
            Ok(Some(map))
        }
        Err(e) => {
            warn!("Corrupted salt cache at {}: {e}", path.display());
            Ok(None)
        }
    }
}

// ---------------------------------------------------------------------------
// Read Path — owned map via rkyv
// ---------------------------------------------------------------------------

/// Read-only salt cache backed by an owned deserialized map.
///
/// Used during **encryption** to look up previously cached `salt/file_id`
/// values. Fully safe: no mmap, no zero-copy aliasing contract.
pub struct SaltCacheReader {
    /// The deserialized cache. Empty if no cache exists or it is corrupted.
    map: HashMap<Vec<u8>, CachedEntry>,
}

impl SaltCacheReader {
    /// Open the salt cache for the given git dir (see
    /// [`crate::repo::Repo::git_dir`]).
    ///
    /// If the cache file does not exist or is corrupted, returns an empty
    /// reader (all lookups will return `None`): a missing or corrupt cache
    /// simply means we start fresh (new salts will be generated during
    /// encryption). Fails only when the guarding lock cannot be taken — the
    /// merge guarantee depends on it, so that is an error, not a degradation.
    pub fn load(git_dir: &Path) -> crate::error::Result<Self> {
        Ok(Self {
            map: read_cache_map(git_dir)?.unwrap_or_default(),
        })
    }

    /// Look up a cached entry by repo-relative path key (bytes).
    ///
    /// The `key` should be forward-slash normalized repo-relative path bytes,
    /// computed by the caller.
    ///
    /// Returns `None` if no cache file exists or the key is not cached.
    #[must_use]
    pub fn get(&self, key: &[u8]) -> Option<CachedEntry> {
        self.map.get(key).copied()
    }
}

// ---------------------------------------------------------------------------
// Write Path — mpsc collection + rkyv serialization
// ---------------------------------------------------------------------------

/// Thread-safe sender for cache entries, safe to share across rayon workers.
///
/// Workers call [`insert`](Self::insert) to send `(key, entry)` pairs
/// through an internal `mpsc` channel. After all parallel work completes,
/// the paired [`SaltCacheSaver`] collects and persists the entries.
pub struct SaltCacheSender {
    tx: mpsc::Sender<(Vec<u8>, CachedEntry)>,
}

impl SaltCacheSender {
    /// Send a cache entry for the given repo-relative path key (bytes).
    ///
    /// The `key` should be forward-slash normalized repo-relative path bytes,
    /// computed by the caller.
    ///
    /// This is thread-safe (`&Self`) and non-blocking. Errors (e.g. channel
    /// closed) are silently ignored because cache persistence is non-critical.
    pub fn insert(&self, key: &[u8], entry: CachedEntry) {
        let _ = self.tx.send((key.to_vec(), entry));
    }
}

/// Receiver that collects and persists cache entries to disk.
///
/// Created paired with a [`SaltCacheSender`] via [`create_writer`]. After all
/// parallel work completes, call [`save`](Self::save) to collect entries,
/// merge with any existing on-disk cache, and serialize via rkyv.
///
/// This type is **not** `Sync` — it should only be used on the main thread
/// after rayon work completes.
///
/// # Drop safety
///
/// [`Drop`] is implemented as a safety net: if [`save`](Self::save) is not
/// called (e.g. due to a panic during parallel decryption), any entries
/// already buffered in the channel are still persisted. This honors the
/// module-level contract that partial progress is preserved on error.
pub struct SaltCacheSaver {
    /// `Option` so [`save_inner`] can take it exactly once; subsequent `Drop`
    /// becomes a no-op.
    rx: Option<mpsc::Receiver<(Vec<u8>, CachedEntry)>>,
    git_dir: PathBuf,
}

impl SaltCacheSaver {
    /// Persist all collected entries to disk (best-effort, atomic).
    ///
    /// 1. Collects all `(key, entry)` pairs currently buffered in the channel
    ///    via [`mpsc::Receiver::try_iter`] (non-blocking — by the time this is
    ///    called, all rayon workers have finished, so every sent entry is
    ///    already buffered).
    /// 2. Merges with any existing on-disk cache (existing entries are kept
    ///    only if no new entry overrides them).
    /// 3. Serializes via rkyv and writes atomically to
    ///    `<repo>/.git/<CACHE_FILENAME>`.
    ///
    /// Safe to call exactly once; a paired [`Drop`] impl guards the
    /// panic-on-drop path (logging any failure it cannot propagate).
    ///
    /// Fails when the guarding lock cannot be taken: writing unlocked would
    /// silently risk losing a concurrent process's entries. Serialization or
    /// write failures are logged but not propagated — cache persistence is
    /// non-critical there: losing the cache only means the next encryption
    /// uses fresh salts.
    pub fn save(mut self) -> crate::error::Result<()> {
        self.save_inner()
    }

    fn save_inner(&mut self) -> crate::error::Result<()> {
        // `take()` ensures the body runs at most once across `save()` + `Drop`.
        let Some(rx) = self.rx.take() else {
            return Ok(());
        };

        // Use `try_iter` (non-blocking) rather than `into_iter` so that:
        //   - explicit `save()` does not require the caller to drop the sender first
        //     (removing a brittle ordering contract);
        //   - the `Drop` impl cannot deadlock if the paired `SaltCacheSender` is
        //     dropped after `self` under non-2024 drop ordering.
        // All rayon workers have returned by the time we get here, so every
        // sent entry is already in the channel buffer.
        let mut entries: HashMap<Vec<u8>, CachedEntry> = rx.try_iter().collect();

        if entries.is_empty() {
            debug!("No cache entries to save");
            return Ok(());
        }

        // Merge with existing cache on disk (keep existing entries only when
        // no new entry covers the same path). The whole read-merge-write
        // cycle runs under an exclusive lock so a concurrently running
        // git-se process cannot interleave and lose entries (L-7). The lock
        // is mandatory: proceeding unlocked would silently break exactly
        // that guarantee.
        let path = cache_path(&self.git_dir);
        let mut lock = open_cache_lock(&self.git_dir)?;
        let _guard = lock.try_write().map_err(|e| {
            crate::error::Error::SaltCache(format!(
                "could not lock {} for writing: {e}",
                self.git_dir.join(LOCK_FILENAME).display()
            ))
        })?;
        // The merge read is fail-closed in BOTH directions (2026-07 audit):
        // an UNREADABLE cache must not be silently overwritten (its entries
        // would be lost — the next encryption would churn the whole git
        // history), and a CORRUPT one is preserved under a `.corrupt`
        // suffix before being rebuilt, never just erased.
        match std::fs::read(&path) {
            Ok(existing_bytes) => {
                match rkyv::from_bytes::<HashMap<Vec<u8>, CachedEntry>, RkyvError>(&existing_bytes)
                {
                    Ok(existing) => {
                        for (k, v) in existing {
                            entries.entry(k).or_insert(v);
                        }
                    }
                    Err(e) => {
                        let corpse = fresh_corrupt_path(&path);
                        warn!(
                            "Corrupted salt cache at {} ({e}); preserving it as {} and \
                             rebuilding from the new entries",
                            path.display(),
                            corpse.display()
                        );
                        std::fs::rename(&path, &corpse).map_err(|e| {
                            crate::error::Error::SaltCache(format!(
                                "could not preserve the corrupted salt cache {} as {}: {e}",
                                path.display(),
                                corpse.display()
                            ))
                        })?;
                    }
                }
            }
            // A genuinely absent cache is an empty one.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(crate::error::Error::SaltCache(format!(
                    "could not read the existing salt cache {} ({e}); refusing to overwrite it \
                     and lose its entries",
                    path.display()
                )));
            }
        }

        // Serialize and write atomically.
        match rkyv::to_bytes::<RkyvError>(&entries) {
            Ok(bytes) => {
                if let Err(e) = atomic_write(&path, bytes.as_slice()) {
                    warn!("Failed to save salt cache to {}: {e}", path.display());
                } else {
                    debug!(
                        "Saved salt cache with {} entries to {}",
                        entries.len(),
                        path.display()
                    );
                }
            }
            Err(e) => {
                warn!("Failed to serialize salt cache: {e}");
            }
        }
        Ok(())
    }
}

/// A fresh preservation name for a corrupted cache: `.corrupt` when free,
/// otherwise the first free `.corrupt-N`. Renaming onto an EXISTING file
/// would destroy previously preserved evidence — Unix replaces silently,
/// Windows fails outright (2026-07 audit). `symlink_metadata`, not
/// `exists`: only a genuinely absent name is free (a dangling symlink must
/// not be replaced either). The cache write lock is held, so no concurrent
/// git-se races the choice; the absurd all-taken case falls back to a
/// random suffix rather than ever overwriting.
fn fresh_corrupt_path(path: &Path) -> PathBuf {
    for n in 0..100u32 {
        let candidate = if n == 0 {
            path.with_extension("corrupt")
        } else {
            path.with_extension(format!("corrupt-{n}"))
        };
        if candidate.symlink_metadata().is_err() {
            return candidate;
        }
    }
    path.with_extension(format!("corrupt-{:016x}", rand::random::<u64>()))
}

/// Create a paired sender/saver for collecting cache entries.
///
/// `git_dir` is the per-worktree git dir the cache is persisted to (see
/// [`crate::repo::Repo::git_dir`]). The sender is `Sync` and can be shared
/// across rayon threads. The saver should be kept on the main thread and
/// `.save()`d after parallel work completes. If `.save()` is not called,
/// [`SaltCacheSaver::drop`] will persist any buffered entries as a safety net.
#[must_use]
pub fn create_writer(git_dir: &Path) -> (SaltCacheSender, SaltCacheSaver) {
    let (tx, rx) = mpsc::channel();
    (
        SaltCacheSender { tx },
        SaltCacheSaver {
            rx: Some(rx),
            git_dir: git_dir.to_path_buf(),
        },
    )
}

impl Drop for SaltCacheSaver {
    fn drop(&mut self) {
        // The safety net cannot propagate — a failure here (e.g. the cache
        // lock being unavailable) is at least loud.
        if let Err(e) = self.save_inner() {
            warn!("Failed to persist the salt cache on drop: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn make_entry(salt_byte: u8, file_id_byte: u8) -> CachedEntry {
        CachedEntry {
            salt: [salt_byte; SALT_LEN],
            file_id: [file_id_byte; FILE_ID_LEN],
        }
    }

    #[test]
    fn test_reader_get_from_wrong_path() {
        let dir = TempDir::new().unwrap();
        let reader = SaltCacheReader::load(dir.path()).unwrap();
        assert_eq!(reader.get(b"test.txt"), None);
    }

    #[test]
    fn test_roundtrip_via_sender_and_reader() {
        let dir = TempDir::new().unwrap();
        let git_dir = dir.path().join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();

        let entry1 = make_entry(0x11, 0x22);
        let entry2 = make_entry(0x33, 0x44);

        {
            let (sender, saver) = create_writer(&git_dir);
            sender.insert(b"file1.txt", entry1);
            sender.insert(b"sub/file2.txt", entry2);
            // Drop sender to close the channel before saving.
            drop(sender);
            saver.save().unwrap();
        }

        // Load via reader and verify.
        let reader = SaltCacheReader::load(&git_dir).unwrap();
        assert_eq!(reader.get(b"file1.txt"), Some(entry1));
        assert_eq!(reader.get(b"sub/file2.txt"), Some(entry2));
        assert_eq!(reader.get(b"nonexistent.txt"), None);
    }

    #[test]
    fn test_load_corrupted_file() {
        let dir = TempDir::new().unwrap();
        let git_dir = dir.path().join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();

        let path = cache_path(&git_dir);
        std::fs::write(&path, b"not valid rkyv data").unwrap();

        // Should return a reader with no data (all lookups return None).
        let reader = SaltCacheReader::load(&git_dir).unwrap();
        assert_eq!(reader.get(b"test.txt"), None);
    }

    #[test]
    fn test_overwrite_entry() {
        let dir = TempDir::new().unwrap();
        let git_dir = dir.path().join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();

        let entry1 = make_entry(0x11, 0x22);
        let entry2 = make_entry(0x33, 0x44);

        {
            let (sender, saver) = create_writer(&git_dir);
            sender.insert(b"test.txt", entry1);
            sender.insert(b"test.txt", entry2);
            drop(sender);
            saver.save().unwrap();
        }

        let reader = SaltCacheReader::load(&git_dir).unwrap();
        assert_eq!(reader.get(b"test.txt"), Some(entry2));
    }

    #[test]
    fn test_relative_path_key_persistence() {
        let dir = TempDir::new().unwrap();
        let git_dir = dir.path().join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();

        let entry = make_entry(0x55, 0x66);

        {
            let (sender, saver) = create_writer(&git_dir);
            sender.insert(b"subdir/file.txt", entry);
            drop(sender);
            saver.save().unwrap();
        }

        let reader = SaltCacheReader::load(&git_dir).unwrap();
        assert_eq!(reader.get(b"subdir/file.txt"), Some(entry));
    }

    /// Regression (2026-07 audit): the cache lock is fail-closed. A save
    /// that cannot take the lock must error rather than proceed unlocked
    /// (silently risking another process's entries), and so must a load.
    #[test]
    fn test_cache_lock_is_fail_closed() {
        let dir = TempDir::new().unwrap();
        let git_dir = dir.path().join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();

        // Seed a cache file so the load path actually reaches the lock.
        {
            let (sender, saver) = create_writer(&git_dir);
            sender.insert(b"seed.txt", make_entry(0x01, 0x02));
            drop(sender);
            saver.save().unwrap();
        }

        // A foreign holder (flock-style locks conflict even between two open
        // descriptions of the same process).
        let mut foreign = open_cache_lock(&git_dir).unwrap();
        let foreign_guard = foreign.try_write().unwrap();

        let (sender, saver) = create_writer(&git_dir);
        sender.insert(b"f.txt", make_entry(0x11, 0x22));
        drop(sender);
        let err = saver.save().unwrap_err();
        assert!(
            matches!(err, crate::error::Error::SaltCache(_)),
            "a locked-out save must fail with SaltCache, got {err:?}"
        );
        assert!(
            SaltCacheReader::load(&git_dir).is_err(),
            "a locked-out load must fail rather than read unlocked"
        );

        // Once the holder lets go, both succeed again.
        drop(foreign_guard);
        let (sender, saver) = create_writer(&git_dir);
        sender.insert(b"f.txt", make_entry(0x11, 0x22));
        drop(sender);
        saver.save().unwrap();
        let reader = SaltCacheReader::load(&git_dir).unwrap();
        assert_eq!(reader.get(b"f.txt"), Some(make_entry(0x11, 0x22)));
    }

    /// Regression (2026-07 audit): saving must never silently wipe entries
    /// it could not read. An UNREADABLE existing cache fails the save (the
    /// file is preserved); a CORRUPT one is preserved under a `.corrupt`
    /// suffix before being rebuilt from the new entries.
    #[test]
    fn test_save_never_clobbers_unreadable_or_corrupt_cache() {
        let dir = TempDir::new().unwrap();
        let git_dir = dir.path().join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();
        let path = cache_path(&git_dir);

        // An unreadable cache (a directory at its path: the read fails on
        // every platform, no permission games).
        std::fs::create_dir(&path).unwrap();
        let (sender, saver) = create_writer(&git_dir);
        sender.insert(b"new.txt", make_entry(0x11, 0x22));
        drop(sender);
        let err = saver.save().unwrap_err();
        assert!(
            matches!(err, crate::error::Error::SaltCache(_)),
            "an unreadable cache must fail the save, got {err:?}"
        );
        assert!(path.is_dir(), "the unreadable cache must be preserved");
        std::fs::remove_dir(&path).unwrap();

        // A corrupt cache: preserved under `.corrupt`, then rebuilt.
        std::fs::write(&path, b"not valid rkyv data").unwrap();
        let (sender, saver) = create_writer(&git_dir);
        sender.insert(b"new.txt", make_entry(0x11, 0x22));
        drop(sender);
        saver.save().unwrap();
        assert!(
            path.with_extension("corrupt").is_file(),
            "the corrupt cache must be preserved under a .corrupt suffix"
        );
        let reader = SaltCacheReader::load(&git_dir).unwrap();
        assert_eq!(reader.get(b"new.txt"), Some(make_entry(0x11, 0x22)));
    }

    /// Regression (2026-07 audit): preserving a corrupted cache must never
    /// overwrite an earlier preserved corpse — renaming onto the fixed
    /// `.corrupt` name replaced it silently on Unix (and failed outright on
    /// Windows). A second corruption round gets the next free suffix.
    #[test]
    fn test_corrupt_preservation_never_overwrites_earlier_corpse() {
        let dir = TempDir::new().unwrap();
        let git_dir = dir.path().join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();
        let path = cache_path(&git_dir);

        for round in 0..2u8 {
            std::fs::write(&path, format!("corrupt round {round}")).unwrap();
            let (sender, saver) = create_writer(&git_dir);
            sender.insert(format!("f{round}.txt").as_bytes(), make_entry(0x11, 0x22));
            drop(sender);
            saver.save().unwrap();
        }

        let first = path.with_extension("corrupt");
        let second = path.with_extension("corrupt-1");
        assert!(
            first.is_file() && second.is_file(),
            "every corrupted cache must be preserved, got: {:?}",
            std::fs::read_dir(&git_dir)
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect::<Vec<_>>()
        );
        assert_eq!(std::fs::read(&first).unwrap(), b"corrupt round 0");
        assert_eq!(std::fs::read(&second).unwrap(), b"corrupt round 1");
    }

    /// Regression (2026-07 audit): "the cache does not exist" must be
    /// established UNDER the lock too — a writer holding the lock could be
    /// midway through creating the file, so even the no-cache case must
    /// fail rather than read past the lock.
    #[test]
    fn test_load_locks_even_when_cache_absent() {
        let dir = TempDir::new().unwrap();
        let git_dir = dir.path().join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();
        // No cache file at all — the lock alone decides.
        let mut foreign = open_cache_lock(&git_dir).unwrap();
        let _guard = foreign.try_write().unwrap();
        assert!(
            SaltCacheReader::load(&git_dir).is_err(),
            "load must fail on a held lock even when no cache file exists"
        );
    }

    #[test]
    fn test_merge_with_existing() {
        let dir = TempDir::new().unwrap();
        let git_dir = dir.path().join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();

        let entry_a = make_entry(0xAA, 0xBB);
        let entry_b = make_entry(0xCC, 0xDD);

        // Save initial entry.
        {
            let (sender, saver) = create_writer(&git_dir);
            sender.insert(b"existing.txt", entry_a);
            drop(sender);
            saver.save().unwrap();
        }

        // Save a new entry — the existing one should be preserved via merge.
        {
            let (sender, saver) = create_writer(&git_dir);
            sender.insert(b"new.txt", entry_b);
            drop(sender);
            saver.save().unwrap();
        }

        let reader = SaltCacheReader::load(&git_dir).unwrap();
        assert_eq!(reader.get(b"existing.txt"), Some(entry_a));
        assert_eq!(reader.get(b"new.txt"), Some(entry_b));
    }
}
