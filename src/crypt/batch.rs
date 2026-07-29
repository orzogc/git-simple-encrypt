use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

use dashmap::DashMap;
use log::debug;
use rand::Rng;
use rayon::prelude::*;

use crate::{
    crypt::{
        file::{encrypt_file_to, persist_temp_file, probe_and_rewind},
        header::{FileHeader, HEADER_LEN, HeaderProbe, SALT_LEN},
        key::{KeyCache, Password, get_or_derive_key, split_keys},
        stream::{decrypt_body, new_cipher},
    },
    error::{Error, Result},
};

/// Pre-compute every `(source, destination)` pair and reject conflicts
/// BEFORE the parallel phase: two sources mapped to one destination would
/// race (last-writer-wins while both count as successes), and a destination
/// that IS another source interleaves reads and writes unpredictably
/// (2026-07 audit). Mapping a file onto itself (in-place) is fine.
fn plan_destinations(
    sources: &[PathBuf],
    mapper: &impl Fn(&Path) -> Option<PathBuf>,
) -> Result<Vec<Option<PathBuf>>> {
    let source_set: std::collections::HashSet<&Path> =
        sources.iter().map(PathBuf::as_path).collect();
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    let mut plans = Vec::with_capacity(sources.len());
    for src in sources {
        let dst = mapper(src);
        if let Some(dst) = &dst {
            // A destination that is ANOTHER source's path interleaves that
            // source's read with this write. (Being one's own source is the
            // ordinary in-place case.)
            if dst != src && source_set.contains(dst.as_path()) {
                return Err(Error::BatchDestinationConflict(dst.clone()));
            }
            if !seen.insert(dst.clone()) {
                return Err(Error::BatchDestinationConflict(dst.clone()));
            }
        }
        plans.push(dst);
    }
    Ok(plans)
}

/// Summary of a batch encrypt/decrypt run.
#[derive(Debug, Default)]
pub struct BatchSummary {
    pub total: usize,
    pub succeeded: usize,
    pub skipped: usize,
    pub failed: usize,
    pub errors: Vec<(PathBuf, Error)>,
}

impl BatchSummary {
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Internal: decrypt `src` → `dst` using a shared Argon2 key cache.
fn decrypt_file_to_with_key_cache(
    src: &Path,
    dst: &Path,
    key_cache: &KeyCache,
    master_key: Password<'_>,
) -> Result<Option<FileHeader>> {
    let mut src_file = fs::File::open(src)?;

    if probe_and_rewind(&mut src_file, src)? != HeaderProbe::Encrypted {
        debug!("File not encrypted, skipping: {}", src.display());
        return Ok(None);
    }

    debug!("Decrypting {} → {}", src.display(), dst.display());

    let mut header_bytes = [0u8; HEADER_LEN];
    src_file.read_exact(&mut header_bytes)?;
    let header = *FileHeader::from_bytes(&header_bytes)?;
    let derived_key = get_or_derive_key(key_cache, master_key, &header.salt)?;

    let dst_parent = dst.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dst_parent)?;
    let mut temp_file = crate::utils::temp_file_in(dst_parent)?;

    let (key_enc, _) = split_keys(&derived_key);
    let cipher = new_cipher(&key_enc);
    decrypt_body(&mut src_file, &mut temp_file, &cipher, &header)?;

    drop(src_file);
    persist_temp_file(temp_file, dst, Some(src))?;

    Ok(Some(header))
}

/// Decrypt multiple files in parallel, each to a caller-determined destination.
///
/// `master_key` is the **raw password** (see "Key Semantics" in the
/// [module docs](crate::crypt)).
///
/// The mapper must be **injective**: destinations are pre-computed and
/// checked up front — duplicates, or a destination colliding with another
/// source's path, fail with [`Error::BatchDestinationConflict`] before any
/// work runs (mapping a file onto itself, i.e. in-place, is fine).
pub fn decrypt_files_to<I, P, F>(
    sources: I,
    master_key: Password<'_>,
    mapper: F,
) -> Result<BatchSummary>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path> + Sync,
    F: Fn(&Path) -> Option<PathBuf> + Sync,
{
    let sources: Vec<PathBuf> = sources
        .into_iter()
        .map(|p| p.as_ref().to_path_buf())
        .collect();
    let total = sources.len();

    // Bound the Argon2 cost before any derivation runs: every distinct salt
    // among the encrypted sources costs one.
    crate::crypt::repo::enforce_salt_budget(&sources)?;
    let plans = plan_destinations(&sources, &mapper)?;

    let key_cache: KeyCache = DashMap::new();
    let errors: parking_lot::Mutex<Vec<(PathBuf, Error)>> = parking_lot::Mutex::new(Vec::new());
    let skipped = AtomicUsize::new(0);
    let succeeded = AtomicUsize::new(0);

    sources.par_iter().zip(&plans).for_each(|(src, dst)| {
        let Some(dst) = dst else {
            // `None` means "filtered out by the caller" — count it so that
            // total == succeeded + skipped + failed holds (M-04).
            skipped.fetch_add(1, Ordering::Relaxed);
            return;
        };

        match decrypt_file_to_with_key_cache(src, dst, &key_cache, master_key) {
            Ok(Some(_)) => {
                succeeded.fetch_add(1, Ordering::Relaxed);
            }
            Ok(None) => {
                skipped.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                errors.lock().push((src.clone(), e));
            }
        }
    });

    let errors = errors.into_inner();
    let succeeded = succeeded.load(Ordering::Relaxed);
    let skipped = skipped.load(Ordering::Relaxed);
    let failed = errors.len();

    Ok(BatchSummary {
        total,
        succeeded,
        skipped,
        failed,
        errors,
    })
}

/// Encrypt multiple files in parallel, each from a caller-determined source to
/// a caller-determined destination.
///
/// `master_key` is the **raw password**; Argon2 derivation happens once per
/// batch (all files share one batch salt), not once per file.
///
/// An already-encrypted source is skipped only after being **fully
/// authenticated** against `master_key` (every chunk — the same standard
/// [`crate::crypt::encrypt_repo`] applies): a forged header or another
/// password's ciphertext is an error in the summary, never a silent skip.
///
/// The mapper must be **injective**: destinations are pre-computed and
/// checked up front — duplicates, or a destination colliding with another
/// source's path, fail with [`Error::BatchDestinationConflict`] before any
/// work runs (mapping a file onto itself, i.e. in-place, is fine).
pub fn encrypt_files_to<I, P, F>(
    sources: I,
    master_key: Password<'_>,
    mapper: F,
    zstd: Option<u8>,
) -> Result<BatchSummary>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path> + Sync,
    F: Fn(&Path) -> Option<PathBuf> + Sync,
{
    let sources: Vec<PathBuf> = sources
        .into_iter()
        .map(|p| p.as_ref().to_path_buf())
        .collect();
    let total = sources.len();

    // Authenticating already-encrypted sources costs one Argon2 per distinct
    // salt — bound it before any derivation runs.
    crate::crypt::repo::enforce_salt_budget(&sources)?;
    let plans = plan_destinations(&sources, &mapper)?;

    let mut batch_salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut batch_salt);
    let derived_key = crate::crypt::key::derive_key(master_key, &batch_salt)?;

    let key_cache: KeyCache = DashMap::new();
    let errors: parking_lot::Mutex<Vec<(PathBuf, Error)>> = parking_lot::Mutex::new(Vec::new());
    let skipped = AtomicUsize::new(0);
    let succeeded = AtomicUsize::new(0);

    sources.par_iter().zip(&plans).for_each(|(src, dst)| {
        let Some(dst) = dst else {
            // `None` means "filtered out by the caller" — count it so that
            // total == succeeded + skipped + failed holds (M-04).
            skipped.fetch_add(1, Ordering::Relaxed);
            return;
        };

        match encrypt_file_to(src, dst, &derived_key, batch_salt, None, zstd) {
            Ok(Some(_)) => {
                succeeded.fetch_add(1, Ordering::Relaxed);
            }
            Ok(None) => {
                // Already encrypted: skipping on FORMAT alone would wave
                // through a forged header or another password's ciphertext
                // (2026-07 audit). Authenticate every chunk first — the
                // plaintext goes nowhere.
                match crate::crypt::repo::verify_own_ciphertext(src, master_key, &key_cache) {
                    Ok(true) => {
                        skipped.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(false) => {
                        errors
                            .lock()
                            .push((src.clone(), Error::ForeignCiphertext(src.clone())));
                    }
                    Err(e) => {
                        errors.lock().push((src.clone(), e));
                    }
                }
            }
            Err(e) => {
                errors.lock().push((src.clone(), e));
            }
        }
    });

    let errors = errors.into_inner();
    let succeeded = succeeded.load(Ordering::Relaxed);
    let skipped = skipped.load(Ordering::Relaxed);
    let failed = errors.len();

    Ok(BatchSummary {
        total,
        succeeded,
        skipped,
        failed,
        errors,
    })
}
