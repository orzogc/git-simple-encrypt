mod progress;
pub(crate) mod style;

use std::{
    ffi::OsStr,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::mpsc,
};

use ignore::{WalkBuilder, WalkState};
pub use progress::Progress;
use tempfile::NamedTempFile;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    config::CONFIG_FILE_NAME,
    crypt::{HeaderProbe, MIN_ENCRYPTED_LEN, probe_header},
    error::{Error, Result},
    utils::style::Colorize,
};

/// Format a byte array into a hex string
#[allow(dead_code)]
#[cfg(any(test, debug_assertions))]
#[must_use]
pub fn format_hex(value: &[u8]) -> String {
    use std::fmt::Write;
    value.iter().fold(String::new(), |mut output, b| {
        let _ = write!(output, "{b:02x}");
        output
    })
}

/// Atomically write `data` to `path` by writing to a temp file first, then
/// renaming. This prevents partial writes from corrupting the target file.
///
/// The temp file is `fsync`ed before the rename and the parent directory is
/// synced afterwards (best-effort), so a crash cannot leave a renamed but
/// empty/partial file behind.
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp_file = NamedTempFile::new_in(parent)?;
    temp_file.write_all(data)?;
    temp_file.as_file().sync_all()?;
    temp_file
        .persist(path)
        .map_err(|e| Error::AtomicPersist(path.to_path_buf(), e.to_string()))?;
    sync_dir(parent);
    Ok(())
}

/// Best-effort `fsync` of a directory after an atomic rename into it.
///
/// Unix only; a no-op on other platforms (opening a directory as a file is
/// not portable). Errors are ignored on purpose: durability is a bonus, not
/// a correctness requirement.
#[cfg(unix)]
pub(crate) fn sync_dir(path: &Path) {
    if let Ok(dir) = fs::File::open(path) {
        let _ = dir.sync_all();
    }
}

/// Best-effort `fsync` of a directory (no-op on non-Unix platforms).
#[cfg(not(unix))]
pub(crate) fn sync_dir(_path: &Path) {}

/// Reconstruct a path from the raw bytes produced by `git -z` output.
///
/// With `-z`, git prints filenames verbatim (no C-style quoting), so on Unix
/// the bytes can be used as-is even for non-UTF-8 names. On other platforms
/// the output is treated as UTF-8 (lossy), matching what git for Windows
/// produces.
#[cfg(unix)]
pub(crate) fn git_z_path(bytes: &[u8]) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;
    PathBuf::from(OsStr::from_bytes(bytes))
}

/// Reconstruct a path from the raw bytes produced by `git -z` output.
#[cfg(not(unix))]
pub(crate) fn git_z_path(bytes: &[u8]) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(bytes).into_owned())
}

/// Environment variable that provides the master password non-interactively.
pub const PASSWORD_ENV_VAR: &str = "GIT_SE_PASSWORD";

/// Get the master password for encrypt/decrypt operations.
///
/// Taken from the `GIT_SE_PASSWORD` environment variable when set (and not
/// only whitespace), otherwise prompted interactively. Passwords are never
/// persisted to disk — the variable only avoids the prompt for scripts.
pub fn get_password(prompt: &str) -> Result<Zeroizing<String>> {
    if let Ok(mut pw) = std::env::var(PASSWORD_ENV_VAR) {
        let trimmed = pw.trim().to_string();
        // Scrub the raw env string promptly; the variable itself remains in
        // the process environment, which is why the env-var mechanism is
        // documented as weaker than interactive entry.
        pw.zeroize();
        if !trimmed.is_empty() {
            return Ok(Zeroizing::new(trimmed));
        }
    }
    prompt_password(prompt)
}

/// Whether the password will come from [`PASSWORD_ENV_VAR`] rather than a
/// prompt. Used to skip interactive confirmation for env-provided passwords.
///
/// The copy `env::var` hands back is scrubbed before it drops. That copy is
/// short-lived and the variable still sits in the process environment either
/// way — but leaving a plain `String` of the password to drop unscrubbed
/// contradicted the documented "only ever held in `Zeroizing`" guarantee.
#[must_use]
pub fn password_from_env() -> bool {
    std::env::var(PASSWORD_ENV_VAR)
        .ok()
        .map(Zeroizing::new)
        .is_some_and(|value| !value.trim().is_empty())
}

/// Prompt for a plain (non-secret) line of input, trimmed.
///
/// Returns an empty string on EOF (non-interactive stdin), which callers
/// should treat as "no choice made".
pub fn prompt_line(prompt: &str) -> Result<String> {
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    Ok(buf.trim().to_string())
}

/// Prompt the user for a password.
///
/// On an interactive terminal the input is read with echo disabled; when
/// stdin is piped/redirected, a plain line read is used instead (there is no
/// echo to suppress, and scripts keep working).
///
/// Returns an empty-password error if the user enters only whitespace. The
/// returned string is wrapped in [`Zeroizing`] so the plaintext is scrubbed
/// from memory on drop.
pub fn prompt_password(prompt: &str) -> Result<Zeroizing<String>> {
    use std::io::IsTerminal as _;
    let mut password = if std::io::stdin().is_terminal() {
        rpassword::prompt_password(prompt)?
    } else {
        print!("{prompt}");
        std::io::stdout().flush()?;
        let mut buf = String::new();
        std::io::stdin().read_line(&mut buf)?;
        buf
    };
    let trimmed = password.trim();
    if trimmed.is_empty() {
        password.zeroize();
        return Err(Error::EmptyPassword);
    }
    // Scrub the raw input buffer too.
    let result = Zeroizing::new(trimmed.to_string());
    password.zeroize();
    Ok(result)
}

/// If the given path is a file, return the file name. Otherwise, return the
/// recursive file name in the given dir.
///
/// The `paths` come from the crypt list or the CLI, i.e. they are an
/// **explicit allowlist**: ignore rules (`.gitignore`, `.ignore`, global git
/// excludes, …) must never hide files the user explicitly asked to encrypt,
/// so all standard filters are disabled. Hidden files are still included.
/// Two things are always excluded, regardless of the list:
///
/// - any `.git` entry (VCS internals must never be encrypted);
/// - the `git_simple_encrypt.toml` config file itself (encrypting it would
///   make the repo unreadable for this tool).
pub fn list_files(
    paths: impl IntoIterator<Item = impl AsRef<Path>>,
    cwd: impl AsRef<Path>,
) -> Result<Vec<PathBuf>> {
    let mut paths_iter = paths.into_iter();
    let cwd = cwd.as_ref();

    // Roots must be repo-relative. This used to be a `debug_assert!`, which
    // turned an ordinary `git-se e /abs/path/file.txt` into a panic in debug
    // builds while release builds carried on regardless.
    let check_relative = |p: &Path| -> Result<()> {
        if p.is_relative() {
            Ok(())
        } else {
            Err(Error::PathNotRelative(p.to_path_buf()))
        }
    };

    let mut builder = if let Some(first_path) = paths_iter.next() {
        check_relative(first_path.as_ref())?;
        WalkBuilder::new(lexical_normalize(&cwd.join(first_path)))
    } else {
        return Ok(Vec::new());
    };

    for p in paths_iter {
        check_relative(p.as_ref())?;
        builder.add(lexical_normalize(&cwd.join(p)));
    }

    let config_file = lexical_normalize(&cwd.join(CONFIG_FILE_NAME));
    builder
        .current_dir(cwd)
        .standard_filters(false)
        .hidden(false)
        .follow_links(false)
        .filter_entry(move |entry| {
            entry.file_name() != OsStr::new(".git") && entry.path() != config_file
        })
        .threads(0);

    let parallel_walker: ignore::WalkParallel = builder.build_parallel();

    let (tx, rx) = mpsc::channel();

    parallel_walker.run(|| {
        let tx = tx.clone();
        Box::new(move |result| {
            match result {
                Ok(entry) => {
                    if let Some(file_type) = entry.file_type()
                        && file_type.is_file()
                    {
                        let _ = tx.send(Ok(entry.into_path()));
                    }
                }
                // Traversal errors (permission denied, IO, unreadable dirs)
                // must surface: a listed-but-unreadable file would otherwise
                // be silently skipped from encryption and checks.
                Err(e) => {
                    let _ = tx.send(Err(e));
                }
            }
            WalkState::Continue
        })
    });

    drop(tx);
    let mut files = Vec::new();
    let mut errors = Vec::new();
    for item in rx {
        match item {
            Ok(p) => files.push(p),
            Err(e) => errors.push(e),
        }
    }
    if let Some(first) = errors.into_iter().next() {
        return Err(Error::Other(format!("failed to traverse path: {first}")));
    }
    Ok(files)
}

/// Normalize a path lexically: removes `.` components (`..` is preserved —
/// path-escape validation happens in [`resolve_target_files`]).
///
/// This keeps walked entry paths comparable (e.g. against the config file
/// path in [`list_files`]' exclusion filter) even when a root was joined
/// with a literal `.`.
fn lexical_normalize(path: &Path) -> PathBuf {
    path.components().collect()
}

/// Reject protected repo-relative paths: anything inside `.git` (compared
/// case-insensitively, covering `.GIT`-style aliases on case-insensitive
/// filesystems) and the `git_simple_encrypt.toml` config file itself.
/// Encrypting those would break the repository or this tool.
pub(crate) fn validate_repo_relative(rel: &Path) -> Result<()> {
    use std::path::Component;
    if let Some(Component::Normal(first)) = rel.components().next()
        && first.eq_ignore_ascii_case(".git")
    {
        return Err(Error::ProtectedPath(rel.to_path_buf()));
    }
    if rel == Path::new(CONFIG_FILE_NAME) {
        return Err(Error::ProtectedPath(rel.to_path_buf()));
    }
    Ok(())
}

/// Whether a repo-relative path is covered by `crypt_list`.
///
/// Matching is **purely lexical** and never touches the filesystem. That is
/// the whole point (H-01): a crypt-list directory that is deleted from the
/// working tree, or simply not materialized by a sparse checkout, must still
/// cover the blobs underneath it. An earlier `repo.join(entry).is_dir()` test
/// silently unlisted exactly those blobs.
///
/// [`Path::starts_with`] compares whole components, so the entry `a` matches
/// `a/b.txt` but not `ab.txt`.
///
/// Protected paths are excluded unconditionally: they can never be encrypted,
/// so demanding that they be encrypted would be an unsatisfiable check
/// (notably with the whole-repo entry `.`).
pub(crate) fn crypt_list_matches(crypt_list: &[String], rel: &Path) -> bool {
    if validate_repo_relative(rel).is_err() {
        return false;
    }
    crypt_list.iter().map(Path::new).any(|entry| {
        if entry.as_os_str() == "." || entry.as_os_str().is_empty() {
            return true; // whole repo listed
        }
        rel == entry || rel.starts_with(entry)
    })
}

/// Validate one explicit target root (CLI path or crypt-list entry):
///
/// 1. lexical: after `absolutize_from` (which resolves `..` textually) the
///    path must stay under `repo_path` — rejects `../outside.txt`;
/// 2. canonical: after resolving ALL symlinks (intermediate ones included)
///    the path must stay under the canonical repo root — rejects escapes via
///    a symlinked component like `link -> /tmp/outside`;
/// 3. the resolved repo-relative path must not be protected
///    ([`validate_repo_relative`]).
///
/// Returns the canonical repo-relative path.
pub(crate) fn validate_target_root(
    entry: &Path,
    repo_path: &Path,
    canonical_repo: &Path,
) -> Result<PathBuf> {
    use path_absolutize::Absolutize as _;
    // path-absolutize v4: `absolutize_from` is infallible.
    let abs = entry.absolutize_from(repo_path);
    if !abs.starts_with(repo_path) {
        return Err(Error::PathEscapesRepo(abs.into_owned()));
    }
    // canonicalize resolves symlinks in every component; a nonexistent entry
    // is an error here (stale crypt-list entry or CLI typo).
    let canonical = abs
        .canonicalize()
        .map_err(|_| Error::PathNotExist(abs.into_owned()))?;
    if !canonical.starts_with(canonical_repo) {
        return Err(Error::PathEscapesRepo(canonical));
    }
    // strip_prefix is guaranteed by the starts_with check above
    let rel = canonical
        .strip_prefix(canonical_repo)
        .unwrap()
        .to_path_buf();
    validate_repo_relative(&rel)?;
    Ok(rel)
}

// --- Reporting & Progress Helpers ---

/// Maximum number of files to display individually before collapsing.
const REPORT_LIST_LIMIT: usize = 10;

/// Print a pre-operation report listing the target files and total count.
/// If the list exceeds `REPORT_LIST_LIMIT`, show the first few and summarize
/// the rest as "... and N more files".
pub fn print_pre_report(action: &str, files: &[impl AsRef<Path>], repo_path: &Path) {
    let count = files.len();
    println!(
        "\n{} {} {}",
        action.bold(),
        format!("({count} files)").cyan(),
        ":".dimmed()
    );

    for f in &files[..count.min(REPORT_LIST_LIMIT)] {
        let relative =
            pathdiff::diff_paths(f.as_ref(), repo_path).unwrap_or_else(|| f.as_ref().to_path_buf());
        println!("  {}", relative.display());
    }

    if count > REPORT_LIST_LIMIT {
        let remaining = count - REPORT_LIST_LIMIT;
        println!("  {}", format!("... and {remaining} more files").dimmed());
    }
    println!();
}

/// Print a post-operation summary report.
pub fn print_post_report(action: &str, total: usize, skipped: usize, failed: usize) {
    let succeeded = total - skipped - failed;
    let label = format!("{action} complete").bold();

    if failed > 0 {
        println!(
            "\n{}: {} succeeded, {} skipped, {} {}",
            label,
            succeeded.to_string().green(),
            skipped.to_string().yellow(),
            failed.to_string().red(),
            "failed".red(),
        );
    } else {
        println!(
            "\n{}: {} succeeded, {} skipped",
            label,
            succeeded.to_string().green(),
            skipped.to_string().yellow(),
        );
    }
}

/// Format-probe a single file on disk.
///
/// Reads up to [`MIN_ENCRYPTED_LEN`] bytes — enough to tell a real encrypted
/// file from a bare or crafted header — and defers the verdict to
/// [`probe_header`]. This is a **format check, not a cryptographic
/// authentication**. Returns an error only if the file cannot be read.
pub fn probe_file(path: &Path) -> Result<HeaderProbe> {
    let mut file = fs::File::open(path)?;
    let mut buf = Vec::with_capacity(MIN_ENCRYPTED_LEN);
    // A short read is meaningful here (it proves the file cannot hold a
    // complete chunk), so read to EOF rather than using `read_exact`.
    (&mut file)
        .take(MIN_ENCRYPTED_LEN as u64)
        .read_to_end(&mut buf)?;
    Ok(probe_header(&buf))
}

/// Whether a single file is a well-formed encrypted file.
///
/// Convenience wrapper over [`probe_file`] for call sites that only need to
/// count encrypted files; anything malformed counts as *not* encrypted.
pub fn is_file_encrypted(path: &Path) -> Result<bool> {
    Ok(probe_file(path)? == HeaderProbe::Encrypted)
}

/// Resolve the target file list for the repo. If `paths` is empty, use the
/// crypt list from the config; otherwise, use the given paths.
///
/// Every entry (explicit CLI paths and crypt-list entries alike) must stay
/// inside the repository; an entry that escapes the repo root (e.g.
/// `../outside.txt`, possibly hand-edited into the config) is an error, so
/// that encrypt/decrypt/check can never touch files outside the repo.
///
/// The result is sorted and deduplicated: overlapping entries (e.g. a
/// directory and a file inside it) must not cause the same file to be
/// processed twice in one parallel run.
pub fn resolve_target_files(
    paths: &[PathBuf],
    crypt_list: &[String],
    repo_path: &Path,
) -> Result<Vec<PathBuf>> {
    // Canonical repo root, computed once: validates every root against
    // symlink-based escapes (H-03) and protected paths (H-02). macOS note:
    // this also normalizes /var -> /private/var style repo paths.
    let canonical_repo = repo_path
        .canonicalize()
        .unwrap_or_else(|_| repo_path.to_path_buf());

    // Walk the VALIDATED repo-relative roots, not the caller's originals: they
    // are relative by construction (so an absolute CLI path is no longer a
    // precondition violation) and symlink-resolved (so the walk starts exactly
    // where validation concluded it was safe to start).
    let roots: Vec<PathBuf> = if paths.is_empty() {
        crypt_list
            .iter()
            .map(|entry| validate_target_root(Path::new(entry), repo_path, &canonical_repo))
            .collect::<Result<_>>()?
    } else {
        paths
            .iter()
            .map(|entry| validate_target_root(entry, repo_path, &canonical_repo))
            .collect::<Result<_>>()?
    };

    let mut files = list_files(&roots, repo_path)?;
    files.sort_unstable();
    files.dedup();

    // Re-check every resolved file (H-03). The walk does not follow symlinks,
    // so this mainly guards against a root's directory components being
    // swapped for a link between validation and traversal. It narrows the
    // window rather than closing it: a strong guarantee needs directory
    // handles (openat2 RESOLVE_BENEATH), which is tracked separately.
    for file in &files {
        let canonical = file
            .canonicalize()
            .map_err(|_| Error::PathNotExist(file.clone()))?;
        if !canonical.starts_with(&canonical_repo) {
            return Err(Error::PathEscapesRepo(canonical));
        }
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use path_absolutize::Absolutize as _;

    use super::*;

    #[test]
    fn test_list_files() {
        let paths = vec!["docs", ".gitignore", "src"]
            .into_iter()
            .map(PathBuf::from);
        let res = list_files(paths, ".")
            .unwrap()
            .into_iter()
            .map(|x| x.absolutize().unwrap().to_path_buf())
            .collect::<Vec<_>>();
        dbg!(&res);
        assert!(
            res.contains(
                &Path::new("docs/README_zh-CN.md")
                    .absolutize()
                    .unwrap()
                    .to_path_buf()
            )
        );
        assert!(res.contains(&Path::new(".gitignore").absolutize().unwrap().to_path_buf()));
        assert!(
            res.contains(
                &Path::new("src/utils/mod.rs")
                    .absolutize()
                    .unwrap()
                    .to_path_buf()
            )
        );
        assert!(!res.contains(&Path::new("docs/").absolutize().unwrap().to_path_buf()));
    }

    /// Traversal errors must surface (M-02): a nonexistent root is an error,
    /// not a silent skip.
    #[test]
    fn test_list_files_errors_on_missing_root() {
        assert!(list_files(["some_thing_not_exist"], ".").is_err());
    }

    #[test]
    fn test_get_password_from_env() {
        // SAFETY: test process; no other test in this binary reads this var.
        unsafe { std::env::set_var(PASSWORD_ENV_VAR, "env-pw") };
        assert!(password_from_env());
        let pw = get_password("this prompt is never shown: ").unwrap();
        assert_eq!(pw.as_str(), "env-pw");
        unsafe { std::env::remove_var(PASSWORD_ENV_VAR) };
        assert!(!password_from_env());
    }

    #[test]
    fn test_cwd() {
        assert_eq!(
            list_files([".gitignore"], Path::new(".").absolutize().unwrap()).unwrap(),
            vec![Path::new(".gitignore").absolutize().unwrap()]
        );
        assert_eq!(
            list_files(["lib.rs"], Path::new("src").absolutize().unwrap()).unwrap(),
            vec![Path::new("src/lib.rs").absolutize().unwrap()]
        );
    }
}
