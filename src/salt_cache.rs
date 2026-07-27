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
//! (last-writer-wins would silently drop entries written by the loser).
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
/// writers take write locks). Best-effort: locking failures degrade to
/// unlocked operation rather than breaking encryption.
fn open_cache_lock(git_dir: &Path) -> Option<fd_lock::RwLock<std::fs::File>> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(git_dir.join(LOCK_FILENAME))
        .ok()?;
    Some(fd_lock::RwLock::new(file))
}

/// Read the cache file and deserialize it, under a shared lock. `None` when
/// missing or corrupted (a fresh start is not an error).
fn read_cache_map(git_dir: &Path) -> Option<HashMap<Vec<u8>, CachedEntry>> {
    let path = cache_path(git_dir);
    if !path.exists() {
        debug!("Salt cache not found at {}", path.display());
        return None;
    }
    let lock = open_cache_lock(git_dir);
    let _guard = lock.as_ref().and_then(|l| {
        l.read()
            .map_err(|e| warn!("Failed to lock salt cache for reading: {e}"))
            .ok()
    });
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            warn!("Failed to read salt cache at {}: {e}", path.display());
            return None;
        }
    };
    match rkyv::from_bytes::<HashMap<Vec<u8>, CachedEntry>, RkyvError>(&bytes) {
        Ok(map) => {
            debug!(
                "Loaded salt cache ({} entries) from {}",
                map.len(),
                path.display()
            );
            Some(map)
        }
        Err(e) => {
            warn!("Corrupted salt cache at {}: {e}", path.display());
            None
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
    /// reader (all lookups will return `None`). This never fails — a missing
    /// or corrupt cache simply means we start fresh (new salts will be
    /// generated during encryption).
    #[must_use]
    pub fn load(git_dir: &Path) -> Self {
        Self {
            map: read_cache_map(git_dir).unwrap_or_default(),
        }
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
    /// panic-on-drop path. Errors are logged but not propagated because cache
    /// persistence is non-critical: losing the cache only means the next
    /// encryption uses fresh salts.
    pub fn save(mut self) {
        self.save_inner();
    }

    fn save_inner(&mut self) {
        // `take()` ensures the body runs at most once across `save()` + `Drop`.
        let Some(rx) = self.rx.take() else {
            return;
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
            return;
        }

        // Merge with existing cache on disk (keep existing entries only when
        // no new entry covers the same path). The whole read-merge-write
        // cycle runs under an exclusive lock so a concurrently running
        // git-se process cannot interleave and lose entries (L-7); locking
        // is advisory/best-effort and degrades to unlocked operation.
        let path = cache_path(&self.git_dir);
        let mut lock = open_cache_lock(&self.git_dir);
        let _guard = lock.as_mut().and_then(|l| {
            l.write()
                .map_err(|e| warn!("Failed to lock salt cache for writing: {e}"))
                .ok()
        });
        if path.exists()
            && let Ok(existing_bytes) = std::fs::read(&path)
            && let Ok(existing) =
                rkyv::from_bytes::<HashMap<Vec<u8>, CachedEntry>, RkyvError>(&existing_bytes)
        {
            for (k, v) in existing {
                entries.entry(k).or_insert(v);
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
    }
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
        self.save_inner();
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
        let reader = SaltCacheReader::load(dir.path());
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
            saver.save();
        }

        // Load via reader and verify.
        let reader = SaltCacheReader::load(&git_dir);
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
        let reader = SaltCacheReader::load(&git_dir);
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
            saver.save();
        }

        let reader = SaltCacheReader::load(&git_dir);
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
            saver.save();
        }

        let reader = SaltCacheReader::load(&git_dir);
        assert_eq!(reader.get(b"subdir/file.txt"), Some(entry));
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
            saver.save();
        }

        // Save a new entry — the existing one should be preserved via merge.
        {
            let (sender, saver) = create_writer(&git_dir);
            sender.insert(b"new.txt", entry_b);
            drop(sender);
            saver.save();
        }

        let reader = SaltCacheReader::load(&git_dir);
        assert_eq!(reader.get(b"existing.txt"), Some(entry_a));
        assert_eq!(reader.get(b"new.txt"), Some(entry_b));
    }
}
