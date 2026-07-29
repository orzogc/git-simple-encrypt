use std::{
    fmt::Write,
    path::{Path, PathBuf},
};

use dashmap::DashMap;
use pathdiff::diff_paths;
use rand::prelude::*;
use rayon::prelude::*;

use crate::{
    config::{CONFIG_FILE_NAME, Config},
    crypt::{
        file::{
            PreparedWrite, prepare_decrypt_file, prepare_encrypt_file, prepare_reencrypt_file,
            record_salt_cache,
        },
        header::{CHUNK_SIZE, FileHeader, HEADER_LEN, MIN_ENCRYPTED_LEN, NONCE_LEN, SALT_LEN},
        key::{KeyCache, Password, get_or_derive_key, split_keys},
        stream::{check_first_chunk, check_first_chunk_with_key, decrypt_body, new_cipher},
        txn::Transaction,
    },
    error::{Error, Result},
    repo::{IndexPath, Repo},
    salt_cache::{self, CacheRef},
    utils::{
        CryptPolicy, Progress, is_file_encrypted, print_post_report, print_pre_report,
        resolve_target_files, style::Colorize,
    },
};

/// Maximum number of individual failures listed before collapsing.
const REPORT_ERROR_LIMIT: usize = 10;

/// Compute a repo-relative cache key from a file path.
///
/// Separators are unified to `/` **on Windows only**. On Unix a backslash is
/// an ordinary filename byte, so translating it merged `a/b` and `a\b` onto
/// one key: whichever decrypted last overwrote the other's entry, and the
/// next encrypt handed both files the same salt and `file_id` — destroying
/// the cross-file uniqueness the `FILE_ID` exists to provide.
#[must_use]
pub fn cache_key(file_path: &Path, repo_path: &Path) -> Vec<u8> {
    let relative = if file_path.is_absolute() {
        diff_paths(file_path, repo_path).unwrap_or_else(|| file_path.to_path_buf())
    } else {
        file_path.to_path_buf()
    };
    #[allow(unused_mut)]
    let mut bytes = relative.into_os_string().into_encoded_bytes();
    #[cfg(windows)]
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

/// Bytes needed from an encrypted blob to verify its first chunk:
/// header + nonce + full chunk ciphertext + tag.
const VERIFY_BLOB_CAP: usize = HEADER_LEN + NONCE_LEN + CHUNK_SIZE + 16;

/// How many **distinct salts** password verification against `HEAD` will run
/// Argon2 for before giving up indeterminate.
///
/// Verifying "any single anchor matches" means trying every genuine-looking
/// anchor, and each new salt costs one expensive derivation. An attacker who
/// controls the repository (e.g. a cloned one) can commit hundreds of small
/// forged anchors with distinct salts — no password needed — and turn an
/// ordinary `git-se e` into a pure CPU burn. The budget bounds that cost; on
/// exhaustion verification fails closed with
/// [`Error::PasswordVerificationIndeterminate`] — never `Mismatch` (which
/// would falsely accuse a correct password) and never `Unverifiable` (which
/// would wave a wrong one through).
///
/// The default is small on purpose: anchors share the batch salt of the run
/// that encrypted them, so distinct salts ≈ distinct encryption batches —
/// typical histories need only a handful, and a correct password matches the
/// FIRST genuine anchor anyway (budget exhaustion with a correct password
/// means the genuine anchors are buried behind that many forged or
/// differently-salted ones). Histories that legitimately exceed the default
/// can raise it explicitly via [`HEAD_ANCHOR_BUDGET_ENV`] rather than making
/// every run pay a large worst case.
#[cfg(not(test))]
const DEFAULT_HEAD_ANCHOR_BUDGET: usize = 8;
/// Kept tiny in tests so the budget path is exercised without minutes of CI.
#[cfg(test)]
const DEFAULT_HEAD_ANCHOR_BUDGET: usize = 2;

/// Environment variable that raises the distinct-salt Argon2 budget for HEAD
/// password verification (see [`DEFAULT_HEAD_ANCHOR_BUDGET`]). An explicit,
/// deliberate knob — not something an attacker-controlled repo can set.
const HEAD_ANCHOR_BUDGET_ENV: &str = "GIT_SE_HEAD_ANCHOR_BUDGET";

/// The effective distinct-salt budget for this run.
fn head_anchor_budget() -> usize {
    std::env::var(HEAD_ANCHOR_BUDGET_ENV)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_HEAD_ANCHOR_BUDGET)
}

/// The policy that selects password anchors in `HEAD`.
///
/// Taken from `HEAD`'s own copy of the config, **not** the working tree:
/// emptying `crypt_list` locally without committing it used to drop every
/// committed anchor, so a wrong password looked like a first-time encryption
/// and was accepted (H-06). The working-tree list is unioned in, so it can
/// only ever *add* candidates.
///
/// "HEAD has no config" (a fresh history) is distinguished from "HEAD has
/// one that cannot be read": the first is ordinary, the second must fail
/// closed. Folding the read error into "no config", as this used to, waved a
/// wrong password through while the code comments claimed the opposite.
fn head_policy(repo: &Repo) -> Result<CryptPolicy> {
    let mut list = repo.conf.crypt_list.clone();
    // `ls-tree` answers from the tree alone, so a config whose blob is
    // corrupt or unreadable still shows up here.
    let tree_entry = repo.run_with_output(&["ls-tree", "HEAD", "--", CONFIG_FILE_NAME])?;
    if tree_entry.trim().is_empty() {
        return CryptPolicy::try_new(&list);
    }
    let bytes = repo
        .run_with_output_bytes(&["cat-file", "blob", &format!("HEAD:{CONFIG_FILE_NAME}")])
        .map_err(|e| {
            Error::Config(format!(
                "HEAD's {CONFIG_FILE_NAME} exists but could not be read ({e}); cannot determine \
                 which committed files anchor the password. Fix the object, or pass \
                 --allow-password-change to skip the check"
            ))
        })?;
    let text = String::from_utf8(bytes)
        .map_err(|e| Error::Config(format!("HEAD's {CONFIG_FILE_NAME} is not UTF-8: {e}")))?;
    // Fail closed: an unparsable committed policy means we cannot know which
    // committed files are anchors, and guessing low would silently accept a
    // changed password.
    let head = Config::parse_crypt_list(&text).map_err(|e| {
        Error::Config(format!(
            "HEAD's {CONFIG_FILE_NAME} does not parse ({e}); cannot determine which committed \
             files anchor the password. Fix and commit the config, or pass \
             --allow-password-change to skip the check"
        ))
    })?;
    list.extend(head);
    CryptPolicy::try_new(&list)
}

/// Candidate anchors: committed regular-file blobs the HEAD policy covers and
/// that are at least large enough to be encrypted.
///
/// `--long` carries the object size, so blobs that cannot possibly hold a
/// header plus one chunk are discarded without any I/O.
fn head_anchor_candidates(repo: &Repo, policy: &CryptPolicy) -> Result<Vec<IndexPath>> {
    let out = repo.run_with_output_bytes(&["ls-tree", "-r", "-z", "--long", "HEAD"])?;
    let mut candidates = Vec::new();
    for record in out.split(|&b| b == 0).filter(|s| !s.is_empty()) {
        // `<mode> SP <type> SP <oid> SP <size> TAB <path>`
        let Some(tab) = record.iter().position(|&b| b == b'\t') else {
            continue;
        };
        let (meta, path) = record.split_at(tab);
        let raw = &path[1..];
        let rel = crate::utils::git_z_path(raw);
        let meta = String::from_utf8_lossy(meta);
        let mut fields = meta.split_whitespace();
        let mode = fields.next().unwrap_or_default();
        let kind = fields.next().unwrap_or_default();
        let _oid = fields.next();
        let size: u64 = fields.next().and_then(|s| s.parse().ok()).unwrap_or(0);

        if kind != "blob" || !matches!(mode, "100644" | "100755") {
            continue;
        }
        if size < MIN_ENCRYPTED_LEN as u64 || !policy.matches(&rel) {
            continue;
        }
        candidates.push(IndexPath {
            raw: raw.to_vec(),
            path: rel,
        });
    }
    Ok(candidates)
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
/// Errors are **not** folded into `Unverifiable`. A broken git, an unreadable
/// tree or an unparsable committed policy all used to read as "there is
/// nothing to verify against", which quietly waved a wrong password through;
/// they are now hard failures. Only a genuine absence of committed ciphertext
/// yields `Unverifiable`.
///
/// Candidates are derived internally rather than taken as an argument, so no
/// caller can narrow them: passing only the files of the current run used to
/// let `git-se e new-file.txt` skip the check entirely (H-06).
pub fn verify_password_against_head(
    repo: &Repo,
    password: Password<'_>,
) -> Result<HeadPasswordCheck> {
    // Distinguish "no commits yet" from "git cannot run": the first is an
    // ordinary fresh repo, the second must never read as "nothing to verify".
    if repo.run(&["rev-parse", "--git-dir"]).is_err() {
        return Err(Error::Git(
            "cannot run git to verify the password against HEAD".to_string(),
        ));
    }
    if repo.run(&["rev-parse", "--verify", "HEAD"]).is_err() {
        // A genuinely unborn branch means a repository with no commits
        // anywhere — no anchors can exist by definition. A HEAD that fails
        // to resolve while history DOES exist (a corrupt or repointed ref)
        // must never read as "nothing to verify against".
        let has_commits = repo
            .run_with_output(&["rev-list", "--all", "-n", "1"])
            .map_or(true, |out| !out.trim().is_empty()); // cannot tell → assume history exists → fail closed
        if has_commits {
            return Err(Error::Git(
                "HEAD cannot be resolved although the repository has commits; refusing to \
                 treat that as 'nothing to verify the password against'"
                    .to_string(),
            ));
        }
        return Ok(HeadPasswordCheck::Unverifiable); // genuinely fresh repository
    }

    let policy = head_policy(repo)?;
    let candidates = head_anchor_candidates(repo, &policy)?;
    // Probe the leading bytes of EVERY candidate in one batched pass — cheap,
    // and the only way to keep a tree full of plaintext from pushing a real
    // anchor past a fixed scan budget. Only blobs that probe as genuine
    // GITSE format proceed to the expensive AEAD below.
    let probes = repo.read_blob_prefixes("HEAD:", &candidates, MIN_ENCRYPTED_LEN)?;

    // Authenticate EVERY genuine anchor until one matches: the semantic is
    // "any single success is proof the password was used before", and
    // capping the attempts let a matching anchor hide behind eight
    // non-matching ones, flipping the verdict to Mismatch for a correct
    // password. The cost is bounded differently — one Argon2 per distinct
    // salt, cached across anchors, and the distinct-salt count itself is
    // budgeted (see MAX_HEAD_ANCHOR_DERIVATIONS) so forged anchors cannot
    // turn verification into unbounded CPU burn.
    let key_cache: KeyCache = DashMap::new();
    let budget = head_anchor_budget();
    let mut derivations = 0usize;
    let mut tried = 0;
    for (entry, probe) in candidates.iter().zip(probes) {
        let Some(probe) = probe else { continue };
        // Committed in plaintext or malformed — not a usable anchor. Same
        // strict probe as everywhere else (M-01), framing included.
        if !probe.is_encrypted() {
            continue;
        }
        tried += 1;
        let mut spec = std::ffi::OsString::from("HEAD:");
        spec.push(entry.path.as_os_str());
        let blob = repo.run_with_output_bytes_capped(
            &[std::ffi::OsStr::new("show"), spec.as_os_str()],
            VERIFY_BLOB_CAP,
        )?;
        // `ls-tree` said this blob exists and how big it is, so a short read
        // is git failing, not an empty file. Treating it as "no anchor here"
        // would be exactly the fail-open behavior this function must avoid.
        let expected = probe.total_len.min(VERIFY_BLOB_CAP as u64);
        if (blob.len() as u64) < expected {
            return Err(Error::Git(format!(
                "could not read the committed blob HEAD:{} needed to verify the password",
                entry.path.display()
            )));
        }
        // The probe already certified the format, so the header parses.
        let header = FileHeader::read_from(&mut &blob[..])?;
        // A cached salt costs nothing; a NEW one spends from the budget.
        if !key_cache.contains_key(&header.salt) {
            if derivations >= budget {
                return Err(Error::PasswordVerificationIndeterminate(budget));
            }
            derivations += 1;
        }
        let derived_key = get_or_derive_key(&key_cache, password, &header.salt)?;
        // An AEAD failure on one candidate does not conclude Mismatch: the
        // blob could simply be corrupted — other candidates decide.
        if matches!(
            check_first_chunk_with_key(&derived_key, &blob, &header),
            Ok(true)
        ) {
            return Ok(HeadPasswordCheck::Match);
        }
    }
    Ok(if tried > 0 {
        HeadPasswordCheck::Mismatch
    } else {
        HeadPasswordCheck::Unverifiable
    })
}

/// Whether an already-encrypted file authenticates under `password` — every
/// chunk, not just the first.
///
/// Only a full decrypt can tell "ours" from "looks like ours": the header
/// carries no proof of which key produced it, and a first-chunk-only check
/// waves through a multi-chunk file with plaintext appended (the untouched
/// first chunk still authenticates). The plaintext is written nowhere —
/// authentication is the point, not the output.
fn verify_own_ciphertext(
    path: &Path,
    password: Password<'_>,
    key_cache: &KeyCache,
) -> Result<bool> {
    use std::io::Read as _;
    let mut file = std::fs::File::open(path)?;
    let mut header_bytes = [0u8; HEADER_LEN];
    file.read_exact(&mut header_bytes)?;
    let header = *FileHeader::from_bytes(&header_bytes)?;
    // The shared cache keeps one Argon2 per salt across the whole batch:
    // files encrypted in the same run usually share the batch salt.
    let derived_key = get_or_derive_key(key_cache, password, &header.salt)?;
    let (key_enc, _) = split_keys(&derived_key);
    let cipher = new_cipher(&key_enc);
    match decrypt_body(&mut file, &mut std::io::sink(), &cipher, &header) {
        Ok(()) => Ok(true),
        // AEAD or framing failure: not ours, or tampered with.
        Err(Error::DecryptFailed(_) | Error::FileTruncated | Error::TruncatedChunk) => Ok(false),
        Err(e) => Err(e),
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
        && verify_password_against_head(repo, password)? == HeadPasswordCheck::Mismatch
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

            let result = get_or_derive_key(&key_cache, password, &salt)
                .and_then(|derived_key| {
                    prepare_encrypt_file(
                        f,
                        f,
                        &derived_key,
                        salt,
                        cached_file_id,
                        repo.conf.use_zstd.then_some(repo.conf.zstd_level),
                    )
                })
                .and_then(|prepared| match prepared {
                    // Already encrypted — authenticate EVERY chunk before
                    // skipping. Unconditional: `--allow-password-change` only
                    // skips the HEAD anchor check, never per-file integrity —
                    // skipping on format alone (even under the flag) lets
                    // tampered ciphertext, e.g. plaintext appended after a
                    // full leading chunk, sail through encrypt and check
                    // alike.
                    None if !verify_own_ciphertext(f, password, &key_cache)? => {
                        Err(Error::ForeignCiphertext(f.clone()))
                    }
                    other => Ok(other),
                })
                .map_err(|e| Error::Other(format!("Failed to encrypt {}: {e}", f.display())));
            pb.inc(1);
            result
        })
        .collect();

    pb.finish_and_clear();

    let (writes, skipped) = collect_prepared(prepared, target_files.len(), "Encrypt")?;
    let outcome = commit_all(repo.git_dir(), repo.path(), writes)?;

    print_post_report("Encrypt", target_files.len(), skipped, 0);
    debug_assert_eq!(outcome.committed + skipped, target_files.len());

    // The encrypt commit's backups hold PLAINTEXT: a leftover one is a
    // disclosure, so it is an error naming every path, not a log line.
    if !outcome.unremoved_backups.is_empty() {
        return Err(Error::BackupCleanupFailed(outcome.unremoved_backups));
    }
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

/// The result of a fully committed phase two.
pub(super) struct CommitOutcome {
    /// How many files were replaced.
    pub committed: usize,
    /// Backups that could not be removed after the commit. After an
    /// **encrypt** these hold plaintext; after a decrypt or password change,
    /// ciphertext. Never silently dropped either way.
    pub unremoved_backups: Vec<PathBuf>,
}

/// Phase two: replace every destination, or none of them.
///
/// Each destination is backed up before it is replaced and the pairs are
/// journaled, so a failure part-way rolls the earlier files back instead of
/// leaving a mixture. That mattered most for a password change, where a
/// half-committed batch leaves some files on the old password and some on the
/// new one — a state no re-run can repair.
fn commit_all(
    git_dir: &Path,
    worktree_root: &Path,
    writes: Vec<PreparedWrite>,
) -> Result<CommitOutcome> {
    let count = writes.len();
    let mut txn = Transaction::begin(git_dir, worktree_root, &writes)?;
    for (index, write) in writes.into_iter().enumerate() {
        if let Err(e) = txn.commit_one(index, write) {
            let recovery = txn.rollback();
            return Err(if recovery.failed.is_empty() {
                Error::Other(format!(
                    "commit phase failed on file {}/{count}; the {index} files already replaced \
                     were rolled back, so the repository is unchanged: {e}",
                    index + 1
                ))
            } else {
                // A failed rollback must not claim "unchanged": those
                // destinations may still hold NEW content, and the user needs
                // the exact backup paths — which the journal keeps pointing
                // at, so the next command retries the restore.
                let mut msg = format!(
                    "commit phase failed on file {}/{count}, and {} of the replaced files \
                     could not be rolled back — those destinations may still hold NEW \
                     content. The originals are preserved in the backups below, and the \
                     transaction journal was kept (the next git-se command will retry the \
                     restore):",
                    index + 1,
                    recovery.failed.len()
                );
                for (dst, backup) in &recovery.failed {
                    let _ = write!(
                        msg,
                        "\n  - {} (backup: {})",
                        dst.display(),
                        backup.display()
                    );
                }
                let _ = write!(msg, "\nroot cause: {e}");
                Error::Other(msg)
            });
        }
    }
    let unremoved_backups = txn.finish()?;
    Ok(CommitOutcome {
        committed: count,
        unremoved_backups,
    })
}

/// Re-encrypt every listed file from `old_password` to `new_password` as a
/// single all-or-nothing operation.
///
/// Either every file ends up encrypted with the new password, or none of them
/// changes at all. The plaintext is never written to a *destination*: it
/// only ever exists in temp files (H-05). Note the crash caveat documented
/// in the README's Atomicity section — a `SIGKILL` mid-operation can leave
/// such a temp file behind until the sweep collects it.
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

    // Salt for any listed file that is currently plaintext and so has no salt
    // of its own to reuse.
    let mut batch_salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut batch_salt);

    let prepared: Vec<Result<Option<PreparedWrite>>> = target_files
        .par_iter()
        .map(|f| {
            let result = prepare_reencrypt_file(
                f,
                &old_key_cache,
                &new_key_cache,
                old_password,
                new_password,
                batch_salt,
                zstd,
            )
            .map(Some)
            .map_err(|e| Error::Other(format!("Failed to re-encrypt {}: {e}", f.display())));
            pb.inc(1);
            result
        })
        .collect();

    pb.finish_and_clear();

    let (writes, skipped) = collect_prepared(prepared, target_files.len(), "Re-encrypt")?;
    let outcome = commit_all(repo.git_dir(), repo.path(), writes)?;

    print_post_report("Re-encrypt", target_files.len(), skipped, 0);
    debug_assert_eq!(outcome.committed + skipped, target_files.len());

    // A password change also ENCRYPTS the list's plaintext members, so any
    // leftover backup may be plaintext — same severity as after an encrypt,
    // not the "ciphertext only" warning decrypt gets.
    if !outcome.unremoved_backups.is_empty() {
        return Err(Error::BackupCleanupFailed(outcome.unremoved_backups));
    }
    Ok(())
}

/// Report backups that survived a successful commit. Used where the backup
/// provably holds ciphertext (decrypt): worth a loud warning, not an error —
/// the contents are not exposed. (Encrypt and password-change leftovers may
/// be plaintext and become [`Error::BackupCleanupFailed`] instead.)
fn warn_unremoved_backups(unremoved: &[PathBuf]) {
    if unremoved.is_empty() {
        return;
    }
    eprintln!(
        "{}: the operation succeeded, but {} backup file(s) could not be removed; they hold \
         pre-operation ciphertext and are excluded from git. Remove them manually:",
        "WARNING".bold(),
        unremoved.len().to_string().yellow(),
    );
    for backup in unremoved {
        eprintln!("  - {}", backup.display());
    }
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

    // One transaction, exactly like encrypt and password change: either every
    // file lands as plaintext or none does (H-05 — the per-file loop this
    // replaces left a plaintext/ciphertext mixture on any commit-phase
    // failure, with neither journal nor backups to recover from).
    //
    // The salt/file_id entries are collected up front but recorded only after
    // the whole batch committed: a rolled-back run must leave the cache
    // untouched rather than claiming files that were never replaced.
    let cache_entries: Vec<(Vec<u8>, FileHeader)> = writes
        .iter()
        .map(|write| (cache_key(write.destination(), repo.path()), write.header))
        .collect();
    let outcome = commit_all(repo.git_dir(), repo.path(), writes)?;
    for (key, header) in &cache_entries {
        record_salt_cache(
            Some(CacheRef {
                sender: &sender,
                key,
            }),
            header,
        );
    }

    drop(sender);
    saver.save();

    print_post_report("Decrypt", target_files.len(), skipped, 0);
    debug_assert_eq!(outcome.committed + skipped, target_files.len());
    warn_unremoved_backups(&outcome.unremoved_backups);

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::*;
    use crate::repo::Repo;

    /// Initialize a git repo in a temp dir with `crypt_list` covering `anchors`.
    fn init_anchor_repo() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().to_path_buf();
        Command::new("git")
            .args(["init", "-q"])
            .current_dir(&root)
            .output()
            .unwrap();
        std::fs::create_dir(root.join("anchors")).unwrap();
        std::fs::write(
            root.join(crate::config::CONFIG_FILE_NAME),
            "use_zstd = false\nzstd_level = 3\ncrypt_list = [\"anchors\"]\n",
        )
        .unwrap();
        (dir, root)
    }

    /// A 104-byte blob that passes the strict format probe: valid header with
    /// the given salt, one complete (forged — no key behind it) chunk.
    fn fake_anchor(salt: [u8; SALT_LEN]) -> Vec<u8> {
        let header = FileHeader::new(false, salt, FileHeader::generate_file_id());
        let mut blob = header.as_bytes().to_vec();
        blob.extend_from_slice(&[0u8; NONCE_LEN + 16]);
        blob
    }

    fn commit_all(root: &Path) {
        for args in [
            ["add", "-A"].as_slice(),
            [
                "-c",
                "user.email=t@e.com",
                "-c",
                "user.name=t",
                "commit",
                "-qm",
                "x",
            ]
            .as_slice(),
        ] {
            let out = Command::new("git")
                .args(args)
                .current_dir(root)
                .output()
                .unwrap();
            assert!(out.status.success(), "git {args:?} failed: {out:?}");
        }
    }

    /// More distinct salts than the derivation budget must fail CLOSED with
    /// `PasswordVerificationIndeterminate` — never Mismatch (which accuses a
    /// correct password) and never Unverifiable (which waves a wrong one
    /// through). This is the forged-anchor CPU-DoS guard.
    #[test]
    fn test_head_verification_budget_fails_closed() {
        let (_dir, root) = init_anchor_repo();
        // Budget is 2 under cfg(test); three distinct salts exceed it.
        for (i, salt) in [[0x11; SALT_LEN], [0x22; SALT_LEN], [0x33; SALT_LEN]]
            .into_iter()
            .enumerate()
        {
            std::fs::write(root.join(format!("anchors/f{i}.bin")), fake_anchor(salt)).unwrap();
        }
        commit_all(&root);

        let repo = Repo::open(&root).unwrap();
        let result = verify_password_against_head(&repo, Password::new(b"hunter2"));
        assert!(
            matches!(result, Err(Error::PasswordVerificationIndeterminate(_))),
            "expected PasswordVerificationIndeterminate, got {result:?}"
        );
    }

    /// Anchors sharing a salt cost ONE derivation from the budget (the key
    /// cache merges them), so `budget` distinct salts still verify normally.
    #[test]
    fn test_head_verification_merges_same_salt() {
        let (_dir, root) = init_anchor_repo();
        let salt_a = [0xAA; SALT_LEN];
        let salt_b = [0xBB; SALT_LEN];
        // Two distinct salts, four anchors — within the cfg(test) budget of 2.
        for (i, salt) in [salt_a, salt_a, salt_b, salt_a].into_iter().enumerate() {
            std::fs::write(root.join(format!("anchors/f{i}.bin")), fake_anchor(salt)).unwrap();
        }
        commit_all(&root);

        let repo = Repo::open(&root).unwrap();
        let result = verify_password_against_head(&repo, Password::new(b"hunter2")).unwrap();
        assert_eq!(result, HeadPasswordCheck::Mismatch);
    }
}
