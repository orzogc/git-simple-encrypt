use std::path::{Path, PathBuf};

use dashmap::DashMap;
use pathdiff::diff_paths;
use rand::prelude::*;
use rayon::prelude::*;

use crate::{
    crypt::{
        file::{
            PreparedWrite, prepare_decrypt_file, prepare_encrypt_file, prepare_reencrypt_file,
            record_salt_cache,
        },
        header::{CHUNK_SIZE, HEADER_LEN, HeaderProbe, NONCE_LEN, SALT_LEN, probe_header},
        key::{KeyCache, Password, get_or_derive_key},
        stream::check_first_chunk,
    },
    error::{Error, Result},
    repo::Repo,
    salt_cache::{self, CacheRef},
    utils::{
        Progress, is_file_encrypted, print_post_report, print_pre_report, resolve_target_files,
        style::Colorize,
    },
};

/// Maximum number of individual failures listed before collapsing.
const REPORT_ERROR_LIMIT: usize = 10;

/// Compute a repo-relative cache key from a file path.
#[must_use]
pub fn cache_key(file_path: &Path, repo_path: &Path) -> Vec<u8> {
    let relative = if file_path.is_absolute() {
        diff_paths(file_path, repo_path).unwrap_or_else(|| file_path.to_path_buf())
    } else {
        file_path.to_path_buf()
    };
    let mut bytes = relative.into_os_string().into_encoded_bytes();
    for b in &mut bytes {
        if *b == b'\\' {
            *b = b'/';
        }
    }
    bytes
}

/// Outcome of verifying a password against encrypted files committed in `HEAD`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadPasswordCheck {
    /// The password decrypts a committed encrypted file — same as last time.
    Match,
    /// A committed encrypted file exists but the password fails on it.
    Mismatch,
    /// Nothing to verify against (no `HEAD`, or no committed encrypted files).
    Unverifiable,
}

/// Maximum number of candidate files tried during the HEAD verification.
const MAX_VERIFY_CANDIDATES: usize = 8;

/// Bytes needed from an encrypted blob to verify its first chunk:
/// header + nonce + full chunk ciphertext + tag.
const VERIFY_BLOB_CAP: usize = HEADER_LEN + NONCE_LEN + CHUNK_SIZE + 16;

/// Paths committed in `HEAD` that the crypt list covers, as git tree paths.
///
/// Enumerated straight from the `HEAD` tree — **never** from a working-tree
/// walk (H-06). A committed ciphertext anchor that was deleted from disk, or
/// that a sparse checkout never materialized, is still the proof of "the
/// password used last time"; walking the working tree loses exactly those and
/// makes a wrong password look like a first-time encryption.
fn head_anchor_candidates(repo: &Repo) -> Vec<String> {
    let Ok(out) = repo.run_with_output_bytes(&["ls-tree", "-r", "-z", "--name-only", "HEAD"])
    else {
        return Vec::new();
    };
    out.split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(crate::utils::git_z_path)
        .filter(|rel| crate::utils::crypt_list_matches(&repo.conf.crypt_list, rel))
        // Git tree paths always use `/`, even on Windows.
        .filter_map(|rel| rel.to_str().map(|s| s.replace('\\', "/")))
        .collect()
}

/// Verify `password` against the encrypted files committed in `HEAD`, without
/// persisting anything.
///
/// The git history is the natural anchor for "the password used last time":
/// it is exactly the baseline a `git diff` compares against, and it stays in
/// sync across machines on its own. When no committed encrypted file can be
/// found (fresh repo, files never committed encrypted), the result is
/// [`HeadPasswordCheck::Unverifiable`] and callers should proceed silently —
/// in that situation there is no history to bloat with a changed password.
///
/// Candidates are derived internally from the whole crypt list rather than
/// taken as an argument, so no caller can narrow them: passing only the files
/// of the current run used to let `git-se e new-file.txt` skip the check
/// entirely (H-06).
#[must_use]
pub fn verify_password_against_head(repo: &Repo, password: Password<'_>) -> HeadPasswordCheck {
    if repo.run(&["rev-parse", "--verify", "HEAD"]).is_err() {
        return HeadPasswordCheck::Unverifiable;
    }

    let mut tried = 0;
    for rel_str in head_anchor_candidates(repo) {
        if tried >= MAX_VERIFY_CANDIDATES {
            break;
        }
        let blob = repo
            .run_with_output_bytes_capped(&["show", &format!("HEAD:{rel_str}")], VERIFY_BLOB_CAP)
            .unwrap_or_default();
        // Missing, empty, committed in plaintext, or malformed — not a usable
        // verification anchor. Same strict probe as everywhere else (M-01).
        if probe_header(&blob) != HeaderProbe::Encrypted {
            continue;
        }
        tried += 1;
        // Any single success is proof the password was used before. An AEAD
        // failure on one candidate does not conclude Mismatch: the blob could
        // simply be corrupted — other candidates decide.
        if matches!(check_first_chunk(password, &blob), Ok(true)) {
            return HeadPasswordCheck::Match;
        }
    }
    if tried > 0 {
        HeadPasswordCheck::Mismatch
    } else {
        HeadPasswordCheck::Unverifiable
    }
}

/// Read at most `cap` bytes of a file.
fn read_capped(path: &Path, cap: usize) -> Result<Vec<u8>> {
    use std::io::Read as _;
    let file = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    file.take(cap as u64).read_to_end(&mut buf)?;
    Ok(buf)
}

/// Fail fast ([`Error::PasswordCheckFailed`]) if `password` cannot decrypt
/// the first encrypted file found in `target_files`.
///
/// AEAD on the first chunk is ground truth: a wrong password is caught
/// before any file is written. Files that fail to parse fall through — the
/// normal decrypt path reports them per file.
pub fn precheck_password(target_files: &[PathBuf], password: Password<'_>) -> Result<()> {
    if let Some(f) = target_files
        .iter()
        .find(|f| is_file_encrypted(f).unwrap_or(false))
    {
        let blob = read_capped(f, VERIFY_BLOB_CAP)?;
        if matches!(check_first_chunk(password, &blob), Ok(false)) {
            return Err(Error::PasswordCheckFailed(f.clone()));
        }
    }
    Ok(())
}

/// Encrypt given files in the repo, in place.
///
/// `password` is the raw master password, prompted for by the caller — it is
/// never persisted. Unless `allow_password_change` is set, the password is
/// first verified against committed encrypted files (see
/// [`verify_password_against_head`]); a mismatch yields
/// [`Error::PasswordChanged`] so an accidental password change cannot
/// silently re-encrypt everything and bloat the git history.
pub fn encrypt_repo(
    repo: &Repo,
    paths: &[PathBuf],
    password: Password<'_>,
    allow_password_change: bool,
) -> Result<()> {
    if password.is_empty() {
        return Err(Error::EmptyKey);
    }

    let target_files = resolve_target_files(paths, &repo.conf.crypt_list, repo.path())?;
    if target_files.is_empty() {
        return Err(Error::NoFile("encrypt"));
    }

    if !allow_password_change
        && verify_password_against_head(repo, password) == HeadPasswordCheck::Mismatch
    {
        let still_encrypted = target_files
            .iter()
            .filter(|f| is_file_encrypted(f).unwrap_or(false))
            .count();
        return Err(Error::PasswordChanged(still_encrypted));
    }

    print_pre_report("Encrypting", &target_files, repo.path());

    let reader = salt_cache::SaltCacheReader::load(repo.git_dir());
    let key_cache: KeyCache = DashMap::new();

    let mut batch_salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut batch_salt);

    let pb = Progress::new(target_files.len(), "Encrypt");

    // Phase one: transform every file into a temp file beside its target.
    // Nothing on disk changes yet, so a failure anywhere aborts with the repo
    // exactly as it was — no half-encrypted mixture (H-05).
    let prepared: Vec<Result<Option<PreparedWrite>>> = target_files
        .par_iter()
        .map(|f| {
            let relative_key = cache_key(f, repo.path());
            let (salt, cached_file_id) = reader
                .get(&relative_key)
                .map_or((batch_salt, None), |entry| {
                    (entry.salt, Some(entry.file_id))
                });

            let result = get_or_derive_key(&key_cache, password, &salt).and_then(|derived_key| {
                prepare_encrypt_file(
                    f,
                    f,
                    &derived_key,
                    salt,
                    cached_file_id,
                    repo.conf.use_zstd.then_some(repo.conf.zstd_level),
                )
                .map_err(|e| Error::Other(format!("Failed to encrypt {}: {e}", f.display())))
            });
            pb.inc(1);
            result
        })
        .collect();

    pb.finish_and_clear();

    let (writes, skipped) = collect_prepared(prepared, target_files.len(), "Encrypt")?;
    let committed = commit_all(writes)?;

    print_post_report("Encrypt", target_files.len(), skipped, 0);
    debug_assert_eq!(committed + skipped, target_files.len());

    Ok(())
}

/// Split phase-one results into committable writes and a skip count, failing
/// the whole operation if any file failed.
///
/// Dropping the already-prepared writes on the error path is what makes the
/// operation atomic: their temp files are removed and no target was touched.
fn collect_prepared(
    prepared: Vec<Result<Option<PreparedWrite>>>,
    total: usize,
    action: &str,
) -> Result<(Vec<PreparedWrite>, usize)> {
    let mut writes = Vec::with_capacity(prepared.len());
    let mut skipped = 0;
    let mut errors = Vec::new();
    for item in prepared {
        match item {
            Ok(Some(w)) => writes.push(w),
            Ok(None) => skipped += 1,
            Err(e) => errors.push(e),
        }
    }
    if let Some(first) = errors.first() {
        println!(
            "\n{}: {} of {total} files failed; {} — the repository is unchanged.",
            format!("{action} aborted").bold(),
            errors.len().to_string().red(),
            "nothing was written".bold(),
        );
        for e in errors.iter().take(REPORT_ERROR_LIMIT) {
            println!("  - {e}");
        }
        if errors.len() > REPORT_ERROR_LIMIT {
            println!(
                "  {}",
                format!("... and {} more", errors.len() - REPORT_ERROR_LIMIT).dimmed()
            );
        }
        return Err(Error::Other(first.to_string()));
    }
    Ok((writes, skipped))
}

/// Phase two: rename every prepared write into place.
///
/// Each temp file is already fsynced, so this is the narrowest window the
/// filesystem offers. A failure here is still reported, but by then the data
/// is durable on disk — see the recovery note in the README.
fn commit_all(writes: Vec<PreparedWrite>) -> Result<usize> {
    let count = writes.len();
    for (done, write) in writes.into_iter().enumerate() {
        write.commit().map_err(|e| {
            Error::Other(format!(
                "commit phase failed after {done}/{count} files were replaced; \
                 re-run the same command to finish: {e}"
            ))
        })?;
    }
    Ok(count)
}

/// Re-encrypt every listed file from `old_password` to `new_password` as a
/// single all-or-nothing operation.
///
/// Either every file ends up encrypted with the new password, or none of them
/// changes at all. The plaintext is never written to the working tree, so an
/// interrupted password change cannot leave secrets on disk (H-05).
pub fn change_password(
    repo: &Repo,
    old_password: Password<'_>,
    new_password: Password<'_>,
) -> Result<()> {
    if old_password.is_empty() || new_password.is_empty() {
        return Err(Error::EmptyKey);
    }

    let target_files = resolve_target_files(&[], &repo.conf.crypt_list, repo.path())?;
    if target_files.is_empty() {
        return Err(Error::NoFile("re-encrypt"));
    }

    // Ground truth before any work: a wrong old password must fail here, not
    // halfway through the fleet.
    precheck_password(&target_files, old_password)?;

    print_pre_report("Re-encrypting", &target_files, repo.path());

    let old_key_cache: KeyCache = DashMap::new();
    let new_key_cache: KeyCache = DashMap::new();
    let zstd = repo.conf.use_zstd.then_some(repo.conf.zstd_level);
    let pb = Progress::new(target_files.len(), "Re-encrypt");

    let prepared: Vec<Result<Option<PreparedWrite>>> = target_files
        .par_iter()
        .map(|f| {
            let result = prepare_reencrypt_file(
                f,
                &old_key_cache,
                &new_key_cache,
                old_password,
                new_password,
                zstd,
            )
            .map_err(|e| Error::Other(format!("Failed to re-encrypt {}: {e}", f.display())));
            pb.inc(1);
            result
        })
        .collect();

    pb.finish_and_clear();

    let (writes, skipped) = collect_prepared(prepared, target_files.len(), "Re-encrypt")?;
    let committed = commit_all(writes)?;

    print_post_report("Re-encrypt", target_files.len(), skipped, 0);
    debug_assert_eq!(committed + skipped, target_files.len());

    Ok(())
}

/// Decrypt given files in the repo, in place.
///
/// `password` is the raw master password, prompted for by the caller — it is
/// never persisted. A fast pre-check tries the first encrypted target file
/// before any work starts, so a wrong password fails immediately with
/// [`Error::PasswordCheckFailed`] instead of per-file errors.
pub fn decrypt_repo(repo: &Repo, paths: &[PathBuf], password: Password<'_>) -> Result<()> {
    if password.is_empty() {
        return Err(Error::EmptyKey);
    }

    let target_files = resolve_target_files(paths, &repo.conf.crypt_list, repo.path())?;
    if target_files.is_empty() {
        return Err(Error::NoFile("decrypt"));
    }

    // Fast pre-check against the first encrypted target file (AEAD on the
    // first chunk is ground truth; a corrupt file falls through to the
    // normal path, which reports it per file).
    precheck_password(&target_files, password)?;

    print_pre_report("Decrypting", &target_files, repo.path());

    let key_cache: KeyCache = DashMap::new();
    let (sender, saver) = salt_cache::create_writer(repo.git_dir());

    let pb = Progress::new(target_files.len(), "Decrypt");

    // Phase one, as in `encrypt_repo`: decrypt everything into temp files and
    // only start replacing originals once every file has succeeded (H-05).
    let prepared: Vec<Result<Option<PreparedWrite>>> = target_files
        .par_iter()
        .map(|f| {
            let result = prepare_decrypt_file(f, f, Some(&key_cache), password)
                .map_err(|e| Error::Other(format!("Failed to decrypt {}: {e}", f.display())));
            pb.inc(1);
            result
        })
        .collect();

    pb.finish_and_clear();

    let (writes, skipped) = collect_prepared(prepared, target_files.len(), "Decrypt")?;

    // Salt/file_id entries are recorded as each write lands, so a commit-phase
    // failure cannot leave the cache claiming files that were never replaced.
    let mut committed = 0;
    for write in writes {
        let header = write.header;
        let relative_key = cache_key(write.destination(), repo.path());
        write.commit().map_err(|e| {
            Error::Other(format!(
                "commit phase failed after {committed} files were replaced; \
                 re-run the same command to finish: {e}"
            ))
        })?;
        record_salt_cache(
            Some(CacheRef {
                sender: &sender,
                key: &relative_key,
            }),
            &header,
        );
        committed += 1;
    }

    drop(sender);
    saver.save();

    print_post_report("Decrypt", target_files.len(), skipped, 0);
    debug_assert_eq!(committed + skipped, target_files.len());

    Ok(())
}
