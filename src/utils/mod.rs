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
    crypt::{HeaderProbe, MIN_ENCRYPTED_LEN, MalformedReason, framing_is_plausible, probe_header},
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
/// a correctness requirement. Transaction-critical paths use
/// [`sync_dir_strict`] instead.
#[cfg(unix)]
pub(crate) fn sync_dir(path: &Path) {
    if let Ok(dir) = fs::File::open(path) {
        let _ = dir.sync_all();
    }
}

/// Best-effort `fsync` of a directory (no-op on non-Unix platforms).
#[cfg(not(unix))]
pub(crate) fn sync_dir(_path: &Path) {}

/// Strict `fsync` of a directory: a sync failure is an error, not a note.
///
/// The transaction protocol's durability claims (backups durable before the
/// journal points at them, the journal's deletion durable before backups are
/// dropped) only hold if the directory syncs actually happen, so those paths
/// abort on failure here instead of silently weakening the guarantee.
///
/// Unix syncs the directory for real (macOS via `F_FULLFSYNC` — plain
/// `fsync` there does not flush the drive's write cache). Non-Unix
/// platforms have no portable directory sync, so this succeeds as a no-op
/// and the documented guarantee there is process-crash recovery, not
/// power-loss durability.
#[cfg(unix)]
pub(crate) fn sync_dir_strict(path: &Path) -> std::io::Result<()> {
    let dir = fs::File::open(path)?;
    sync_fd_durable(&dir)
}

/// macOS: `fcntl(F_FULLFSYNC)`, the only flush that reaches the drive on
/// APFS/HFS+ (plain `fsync` leaves data in the drive's write cache — this is
/// why SQLite does the same). Filesystems that reject `F_FULLFSYNC` (some
/// network mounts answer EINVAL) fall back to plain `fsync` rather than
/// failing every transaction there.
#[cfg(target_os = "macos")]
fn sync_fd_durable(file: &fs::File) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd as _;
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_FULLFSYNC) } == -1 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINVAL) {
            return file.sync_all();
        }
        return Err(err);
    }
    Ok(())
}

/// Non-macOS Unix: a plain `fsync` is the durable operation.
#[cfg(all(unix, not(target_os = "macos")))]
fn sync_fd_durable(file: &fs::File) -> std::io::Result<()> {
    file.sync_all()
}

/// Strict directory sync (no-op on non-Unix platforms — see the Unix doc).
#[cfg(not(unix))]
pub(crate) fn sync_dir_strict(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// [`atomic_write`] with a strict directory sync: when this returns, the
/// rename is durable (on Unix — see [`sync_dir_strict`]). Used for the
/// transaction journal, where a power cut must neither lose nor resurrect
/// the record.
pub(crate) fn atomic_write_durable(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp_file = NamedTempFile::new_in(parent)?;
    temp_file.write_all(data)?;
    temp_file.as_file().sync_all()?;
    temp_file
        .persist(path)
        .map_err(|e| Error::AtomicPersist(path.to_path_buf(), e.to_string()))?;
    sync_dir_strict(parent)?;
    Ok(())
}

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

/// Prefix for the temp files holding not-yet-committed content.
///
/// Recognizable on purpose: the generic `.tmpXXXXXX` these used to get was
/// indistinguishable from any other tool's leftovers, so a crash-orphaned
/// file (which for decryption holds *plaintext*) could not be swept up or
/// excluded from git. See [`sweep_stale_temp_files`].
pub(crate) const TEMP_PREFIX: &str = ".git-se-tmp.";

/// Prefix for the backup copies taken during a transactional commit.
pub(crate) const BACKUP_PREFIX: &str = ".git-se-bak.";

/// Create a temp file next to `dir` using git-se's recognizable prefix.
///
/// The random part is 16 characters (tempfile's default is 6): a longer,
/// unmistakably-generated shape is what lets the startup sweep collect these
/// without ever touching a user file that merely shares the prefix (see
/// [`sweep_stale_temp_files`]).
pub(crate) fn temp_file_in(dir: &Path) -> std::io::Result<NamedTempFile> {
    tempfile::Builder::new()
        .prefix(TEMP_PREFIX)
        .rand_bytes(16)
        .tempfile_in(dir)
}

/// How old a leftover must be before the sweep removes it. The repository
/// lock (see `crypt::txn`) already keeps a *live* git-se process's files
/// from being swept; this age is a courtesy margin for everything else —
/// above all a user file that merely looks like one of ours.
const SWEEP_MIN_AGE: std::time::Duration = std::time::Duration::from_secs(60 * 60);

/// Whether `name` has the full shape of a temp file git-se creates: the
/// prefix plus 16 random alphanumeric characters ([`temp_file_in`]).
/// Anything less specific is left alone — a shorter suffix is
/// indistinguishable from a user file (`.git-se-tmp.ABC123`), and
/// indistinguishable means "never auto-delete" here.
fn is_generated_temp_name(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix(TEMP_PREFIX) else {
        return false;
    };
    suffix.len() == 16 && suffix.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Whether `name` has the full shape of a transaction backup:
/// `.git-se-bak.<128-bit txn hex>.<index>`. Older shapes (bare digits,
/// 32-bit ids) are NOT matched: they are too easily a user file
/// (`.git-se-bak.2024`), and files the sweep cannot confidently attribute
/// to git-se are never deleted — at worst they linger.
fn is_generated_backup_name(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix(BACKUP_PREFIX) else {
        return false;
    };
    let Some((txn, index)) = suffix.split_once('.') else {
        return false;
    };
    txn.len() == 32
        && txn.bytes().all(|b| b.is_ascii_hexdigit())
        && !index.is_empty()
        && index.bytes().all(|b| b.is_ascii_digit())
}

/// Whether the entry is older than [`SWEEP_MIN_AGE`]. Anything whose age
/// cannot be determined is left alone.
fn is_old_enough(entry: &ignore::DirEntry) -> bool {
    entry
        .metadata()
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|age| age >= SWEEP_MIN_AGE)
}

/// Remove git-se temp and backup files left behind by an interrupted run.
///
/// `NamedTempFile` deletes itself on drop, but `SIGKILL`, a power cut or a
/// panic-free abort never run destructors — and a decryption temp holds
/// **plaintext**. Sweeping at startup bounds how long such a file can sit in
/// the working tree; the git exclude entry (see [`exclude_temp_files`]) stops
/// `git add .` picking one up in the meantime.
///
/// A file is removed only when it has the *full* generated name shape (see
/// [`is_generated_temp_name`]/[`is_generated_backup_name`]) AND is at least
/// [`SWEEP_MIN_AGE`] old — never for merely sharing the prefix, which user
/// files legitimately can. `sweep_backups` is false while an unrecovered
/// transaction journal still exists: its backups are the user's last
/// recovery material. The walk never enters `.git` or the resolved git
/// dirs (`protected`): deleting things under git internals is not ours to do.
pub(crate) fn sweep_stale_temp_files(
    repo_path: &Path,
    sweep_backups: bool,
    protected: &ProtectedDirs,
) {
    let root = repo_path.to_path_buf();
    let protected = protected.clone();
    let walker = WalkBuilder::new(repo_path)
        .standard_filters(false)
        .hidden(false)
        .follow_links(false)
        .filter_entry(move |entry| {
            if entry.file_name().eq_ignore_ascii_case(".git") {
                return false;
            }
            let Ok(rel) = entry.path().strip_prefix(&root) else {
                return true;
            };
            !protected.contains_rel(rel)
        })
        .build_parallel();
    let count = std::sync::atomic::AtomicUsize::new(0);
    walker.run(|| {
        Box::new(|result| {
            if let Ok(entry) = result
                && entry.file_type().is_some_and(|t| t.is_file())
                && let Some(name) = entry.file_name().to_str()
            {
                let generated = is_generated_temp_name(name)
                    || (sweep_backups && is_generated_backup_name(name));
                if generated && is_old_enough(&entry) && fs::remove_file(entry.path()).is_ok() {
                    count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
            WalkState::Continue
        })
    });
    let count = count.into_inner();
    if count > 0 {
        log::warn!(
            "Removed {count} leftover git-se temp file(s) from an interrupted run. If a decrypt \
             was interrupted, those held plaintext — consider whether they were backed up or \
             committed elsewhere."
        );
    }
}

/// Make git ignore git-se's temp and backup files.
///
/// Written to `<git-dir>/info/exclude` rather than `.gitignore` so it is not
/// itself a tracked change. Without it a crash-orphaned plaintext temp file
/// can be swept straight into a commit by `git add .`.
pub(crate) fn exclude_temp_files(git_dir: &Path) {
    let marker = "# git-se: temp and backup files from interrupted runs";
    let body = format!("{marker}\n{TEMP_PREFIX}*\n{BACKUP_PREFIX}*\n");
    let info = git_dir.join("info");
    let exclude = info.join("exclude");
    // Byte-level merge: the exclude file may legitimately hold non-UTF-8
    // pathspecs, and treating an undecodable file as "empty"
    // (`read_to_string().unwrap_or_default()`) used to erase it wholesale.
    // Only a genuinely absent file is "empty": any other read error must NOT
    // be merged over — that would replace rules we could not read with only
    // our own.
    let existing = match fs::read(&exclude) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => {
            log::warn!(
                "Could not read {} ({e}); leaving the git exclude file unchanged — git-se temp \
                 files may not be excluded from `git add` until this is fixed",
                exclude.display()
            );
            return;
        }
    };
    if existing
        .windows(marker.len())
        .any(|w| w == marker.as_bytes())
    {
        return;
    }
    if let Err(e) = fs::create_dir_all(&info) {
        log::warn!(
            "Could not create {} ({e}); git-se temp files are NOT excluded from `git add`",
            info.display()
        );
        return;
    }
    let mut merged = existing;
    if !merged.is_empty() && !merged.ends_with(b"\n") {
        merged.push(b'\n');
    }
    merged.extend_from_slice(body.as_bytes());
    // A crash-orphaned decrypt temp holds PLAINTEXT: if the exclude update
    // fails, `git add .` can sweep one into a commit — that must be a loud
    // warning, not a debug log line. (Re-attempted on every `Repo::open`, so
    // a transient failure self-heals.)
    if let Err(e) = atomic_write(&exclude, &merged) {
        log::warn!(
            "Could not update {} ({e}); git-se temp files are NOT excluded from `git add`",
            exclude.display()
        );
    }
}

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
/// These are always excluded, regardless of the list:
///
/// - any `.git` entry (VCS internals must never be encrypted);
/// - anything under the resolved git dirs (`protected` — a
///   `--separate-git-dir` layout can put them inside the worktree under an
///   arbitrary name);
/// - the `git_simple_encrypt.toml` config file itself (encrypting it would
///   make the repo unreadable for this tool).
pub fn list_files(
    paths: impl IntoIterator<Item = impl AsRef<Path>>,
    cwd: impl AsRef<Path>,
    protected: &ProtectedDirs,
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
    let cwd_owned = cwd.to_path_buf();
    let protected = protected.clone();
    builder
        .current_dir(cwd)
        .standard_filters(false)
        .hidden(false)
        .follow_links(false)
        .filter_entry(move |entry| {
            // Case-insensitive: a `.GIT` directory is git internals too, on
            // any filesystem that resolves it as such.
            if entry.file_name().eq_ignore_ascii_case(".git") || entry.path() == config_file {
                return false;
            }
            // Prune the resolved git dirs when they sit inside the worktree
            // (e.g. `--separate-git-dir`): their name need not be `.git`.
            let Ok(rel) = entry.path().strip_prefix(&cwd_owned) else {
                return true;
            };
            !protected.contains_rel(rel)
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

/// Whether any component of `path` is named `.git`, compared
/// case-insensitively so `.GIT` aliases and case-insensitive filesystems are
/// covered.
///
/// Checking *every* component, not just the first, is what keeps a nested
/// repository's internals out of reach: `inner/.git/config` is as fatal to
/// encrypt as `.git/config` is.
pub(crate) fn has_git_component(path: &Path) -> bool {
    use std::path::Component;
    path.components().any(|c| match c {
        Component::Normal(name) => name.eq_ignore_ascii_case(".git"),
        _ => false,
    })
}

/// Directories no operation may ever read or write.
///
/// These are the repository's **resolved** git dirs (per-worktree and
/// common), as answered by git plumbing. A `--separate-git-dir` layout can
/// place the real git dir inside the worktree under an arbitrary name
/// (`/repo/meta`), where the lexical `.git` name check cannot see it —
/// encrypting `meta/HEAD` destroys the repository just the same.
#[derive(Debug, Clone, Default)]
pub struct ProtectedDirs {
    /// Canonical absolute forms — authoritative for target validation.
    abs: Vec<PathBuf>,
    /// Repo-relative lexical prefixes of the ones inside the worktree — for
    /// policy matching and walk pruning.
    rel: Vec<PathBuf>,
}

impl ProtectedDirs {
    /// Build from the canonical absolute git dirs and the canonical repo
    /// root. A git dir outside the worktree (worktrees, submodules) has no
    /// relative prefix — paths there are already unreachable for targets.
    pub fn new(abs: Vec<PathBuf>, canonical_repo: &Path) -> Self {
        let mut abs = abs;
        abs.sort_unstable();
        abs.dedup();
        let rel = abs
            .iter()
            .filter_map(|d| d.strip_prefix(canonical_repo).ok())
            // The repo root itself can never be a protected dir (`Repo::open`
            // rejects that layout); an empty prefix would match everything.
            .filter(|p| !p.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .collect();
        Self { abs, rel }
    }

    /// Whether `canonical` (a fully resolved absolute path) lies inside a
    /// protected dir.
    pub(crate) fn contains_abs(&self, canonical: &Path) -> bool {
        self.abs.iter().any(|d| canonical.starts_with(d))
    }

    /// Whether a repo-relative path lies inside a protected dir.
    pub(crate) fn contains_rel(&self, rel: &Path) -> bool {
        self.rel.iter().any(|p| rel.starts_with(p))
    }
}

/// Reject protected repo-relative paths: anything inside *any* `.git`
/// directory (see [`has_git_component`]), anything under the resolved git
/// dirs (see [`ProtectedDirs`]), and the `git_simple_encrypt.toml` config
/// file itself. Encrypting those would break a repository or this tool.
pub(crate) fn validate_repo_relative(rel: &Path, protected: &ProtectedDirs) -> Result<()> {
    if has_git_component(rel) || protected.contains_rel(rel) {
        return Err(Error::ProtectedPath(rel.to_path_buf()));
    }
    if rel == Path::new(CONFIG_FILE_NAME) {
        return Err(Error::ProtectedPath(rel.to_path_buf()));
    }
    Ok(())
}

/// Normalize one raw crypt-list entry into the repo-relative form used for
/// lexical matching.
///
/// Entries live in the config as free-form strings, so `secret.txt`,
/// `./secret.txt` and `secret.txt/` all denote the same target and must all
/// match the same blob. The encrypt path used to normalize them (via
/// `canonicalize`) while the staged check compared the raw strings, so
/// `crypt_list = ["./secret.txt"]` was enforced by one and silently ignored
/// by the other.
///
/// Returns `None` for entries that cannot denote a plain repo-relative path
/// (`..`, absolute roots, Windows prefixes). Every caller turns that into a
/// hard error (see [`invalid_crypt_entry`]): silently ignoring such an entry
/// once let the staged check treat `d/../secret.txt` as "no policy" while
/// the encrypt path happily encrypted `secret.txt`.
pub(crate) fn normalize_crypt_entry(entry: &str) -> Option<PathBuf> {
    use std::path::Component;
    let mut out = PathBuf::new();
    for component in Path::new(entry).components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => out.push(part),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(out)
}

/// The shared hard error for a crypt-list entry that is not a plain
/// repo-relative path. The policy builder and target resolution both use it,
/// so all entry points reject the same strings identically (fail-closed for
/// the staged/HEAD policies, a clear config error for the working tree).
pub(crate) fn invalid_crypt_entry(entry: &str) -> Error {
    Error::Config(format!(
        "crypt_list entry {entry:?} is not a plain repo-relative path (`..` and absolute \
         paths are not allowed in the config)"
    ))
}

/// A crypt list normalized once, for repeated lexical matching.
///
/// Matching never touches the filesystem (H-01): a crypt-list directory that
/// is deleted from the working tree, or simply not materialized by a sparse
/// checkout, must still cover the blobs underneath it.
#[derive(Debug, Clone, Default)]
pub(crate) struct CryptPolicy {
    /// Set by the whole-repo entry `.` (or an empty entry).
    whole_repo: bool,
    entries: Vec<PathBuf>,
    /// Resolved git dirs as repo-relative prefixes — never matched, exactly
    /// like `.git` itself (see [`ProtectedDirs`]).
    protected: ProtectedDirs,
}

impl CryptPolicy {
    /// Build a policy from raw crypt-list entries.
    ///
    /// Every entry must be a plain repo-relative path; anything else is a
    /// hard error, never a silent skip. The staged check, the HEAD password
    /// anchors and the working-tree operations all build their policy here,
    /// so they can never disagree about what the config covers.
    pub(crate) fn try_new<S: AsRef<str>>(
        crypt_list: &[S],
        protected: &ProtectedDirs,
    ) -> Result<Self> {
        let mut policy = Self {
            protected: protected.clone(),
            ..Self::default()
        };
        for raw in crypt_list {
            let entry = normalize_crypt_entry(raw.as_ref())
                .ok_or_else(|| invalid_crypt_entry(raw.as_ref()))?;
            if entry.as_os_str().is_empty() {
                policy.whole_repo = true;
            } else {
                policy.entries.push(entry);
            }
        }
        policy.entries.sort_unstable();
        policy.entries.dedup();
        Ok(policy)
    }

    /// Whether the policy covers `rel`, a repo-relative path.
    ///
    /// [`Path::starts_with`] compares whole components, so the entry `a`
    /// matches `a/b.txt` but not `ab.txt`.
    ///
    /// Protected paths never match: they can never be encrypted, so demanding
    /// it would be an unsatisfiable check (notably under the whole-repo `.`).
    pub(crate) fn matches(&self, rel: &Path) -> bool {
        if validate_repo_relative(rel, &self.protected).is_err() {
            return false;
        }
        self.whole_repo
            || self
                .entries
                .iter()
                .any(|entry| rel == entry || rel.starts_with(entry))
    }

    pub(crate) const fn is_empty(&self) -> bool {
        !self.whole_repo && self.entries.is_empty()
    }
}

/// Reject a target reached through a symlink inside the repository.
///
/// `canonicalize` only proves where a path lands *at that instant*; the
/// resolution can change between the check and the `open`/`rename` that
/// follows. Refusing symlinked components removes that whole class of races
/// for target roots — an attacker can no longer repoint an existing link —
/// leaving only the much narrower window in which a real directory is swapped
/// wholesale. See "Threat model" in the README for what remains.
///
/// Only components *inside* the repository are examined. Above the root,
/// symlinks are ordinary setup (macOS `/var` → `/private/var`, a home
/// directory on another volume) and rejecting them would be absurd.
///
/// Shared by ordinary target validation and transaction-journal recovery:
/// a journaled path may lexically sit inside the worktree yet resolve
/// outside it through a symlinked component (`repo/link -> /outside`).
pub(crate) fn reject_symlinked_components(
    abs: &Path,
    repo_path: &Path,
    canonical_repo: &Path,
) -> Result<()> {
    let base = if abs.starts_with(repo_path) {
        repo_path
    } else {
        canonical_repo
    };
    let Ok(rel) = abs.strip_prefix(base) else {
        return Ok(());
    };
    let mut current = base.to_path_buf();
    for component in rel.components() {
        current.push(component);
        if fs::symlink_metadata(&current).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(Error::SymlinkedTarget(current));
        }
    }
    Ok(())
}

/// Validate one explicit target root (CLI path or crypt-list entry):
///
/// 1. lexical (relative entries only): after `absolutize_from` (which
///    resolves `..` textually) the path must stay under `repo_path` —
///    rejects `../outside.txt`;
/// 2. canonical: after resolving ALL symlinks (intermediate ones included)
///    the path must stay under the canonical repo root — rejects escapes via
///    a symlinked component like `link -> /tmp/outside`;
/// 3. the canonical path must not lie inside the resolved git dirs
///    (`protected`) — authoritative even when their name is not `.git`;
/// 4. the resolved repo-relative path must not be protected
///    ([`validate_repo_relative`]).
///
/// Returns the canonical repo-relative path.
pub(crate) fn validate_target_root(
    entry: &Path,
    repo_path: &Path,
    canonical_repo: &Path,
    protected: &ProtectedDirs,
) -> Result<PathBuf> {
    use path_absolutize::Absolutize as _;
    // path-absolutize v4: `absolutize_from` is infallible.
    let abs = entry.absolutize_from(repo_path);
    // The lexical guard applies to RELATIVE entries only. It exists to give
    // `../outside.txt` a clear error without touching the filesystem, which
    // it can do because such an entry is anchored at `repo_path` by
    // construction. An ABSOLUTE entry carries the caller's own spelling of
    // the root, and that need not match ours: `Repo::open` resolves the root
    // through git plumbing, so on macOS it holds `/private/var/...` while a
    // path the caller built from the same directory is still `/var/...`.
    // Comparing those textually reports a false escape. Absolute entries are
    // decided by the canonical check below, which is authoritative either way
    // — it resolves both sides fully before comparing.
    if entry.is_relative() && !abs.starts_with(repo_path) {
        return Err(Error::PathEscapesRepo(abs.into_owned()));
    }
    // canonicalize resolves symlinks in every component; a nonexistent entry
    // is an error here (stale crypt-list entry or CLI typo). `dunce` keeps
    // every canonical path in this crate in one flavor — mixing it with the
    // `\\?\` form std yields on Windows would break the comparison below.
    let canonical =
        dunce::canonicalize(&abs).map_err(|_| Error::PathNotExist(abs.clone().into_owned()))?;
    if !canonical.starts_with(canonical_repo) {
        return Err(Error::PathEscapesRepo(canonical));
    }
    // Git internals under their RESOLVED name (not necessarily `.git`) are as
    // untouchable as `.git` itself.
    if protected.contains_abs(&canonical) {
        return Err(Error::ProtectedPath(canonical));
    }
    // After the escape check, so a symlink that leaves the repository still
    // reports the more specific `PathEscapesRepo`.
    reject_symlinked_components(&abs, repo_path, canonical_repo)?;
    // strip_prefix is guaranteed by the starts_with check above
    let rel = canonical
        .strip_prefix(canonical_repo)
        .unwrap()
        .to_path_buf();
    validate_repo_relative(&rel, protected)?;
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
    let total_len = file.metadata()?.len();
    let mut buf = Vec::with_capacity(MIN_ENCRYPTED_LEN);
    // A short read is meaningful here (it proves the file cannot hold a
    // complete chunk), so read to EOF rather than using `read_exact`.
    (&mut file)
        .take(MIN_ENCRYPTED_LEN as u64)
        .read_to_end(&mut buf)?;
    Ok(match probe_header(&buf) {
        // The whole file is on disk, so its chunk framing can be checked too.
        HeaderProbe::Encrypted if !framing_is_plausible(total_len) => {
            HeaderProbe::Malformed(MalformedReason::BadFraming)
        }
        other => other,
    })
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
/// `protected` carries the resolved git dirs: entries pointing inside them
/// are rejected, and the traversal prunes them.
///
/// The result is sorted and deduplicated: overlapping entries (e.g. a
/// directory and a file inside it) must not cause the same file to be
/// processed twice in one parallel run.
pub fn resolve_target_files(
    paths: &[PathBuf],
    crypt_list: &[String],
    repo_path: &Path,
    protected: &ProtectedDirs,
) -> Result<Vec<PathBuf>> {
    // Canonical repo root, computed once: validates every root against
    // symlink-based escapes (H-03) and protected paths (H-02). macOS note:
    // this also normalizes /var -> /private/var style repo paths.
    let canonical_repo = dunce::canonicalize(repo_path).unwrap_or_else(|_| repo_path.to_path_buf());

    // Walk the VALIDATED repo-relative roots, not the caller's originals: they
    // are relative by construction (so an absolute CLI path is no longer a
    // precondition violation) and symlink-resolved (so the walk starts exactly
    // where validation concluded it was safe to start).
    let roots: Vec<PathBuf> = if paths.is_empty() {
        crypt_list
            .iter()
            .map(|entry| {
                // Config entries obey the policy's lexical rules
                // ([`CryptPolicy::try_new`]): what the staged check matches is
                // exactly what gets encrypted here. `d/../x` must not walk `x`
                // while the matcher sees nothing.
                let normalized =
                    normalize_crypt_entry(entry).ok_or_else(|| invalid_crypt_entry(entry))?;
                validate_target_root(&normalized, repo_path, &canonical_repo, protected)
            })
            .collect::<Result<_>>()?
    } else {
        paths
            .iter()
            .map(|entry| validate_target_root(entry, repo_path, &canonical_repo, protected))
            .collect::<Result<_>>()?
    };

    let mut files = list_files(&roots, repo_path, protected)?;
    files.sort_unstable();
    files.dedup();

    // Re-check every resolved file (H-03). The walk does not follow symlinks,
    // so this mainly guards against a root's directory components being
    // swapped for a link between validation and traversal. It narrows the
    // window rather than closing it: a strong guarantee needs directory
    // handles (openat2 RESOLVE_BENEATH), which is tracked separately.
    for file in &files {
        let canonical = dunce::canonicalize(file).map_err(|_| Error::PathNotExist(file.clone()))?;
        if !canonical.starts_with(&canonical_repo) {
            return Err(Error::PathEscapesRepo(canonical));
        }
        if protected.contains_abs(&canonical) {
            return Err(Error::ProtectedPath(canonical));
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
        let res = list_files(paths, ".", &ProtectedDirs::default())
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
        assert!(list_files(["some_thing_not_exist"], ".", &ProtectedDirs::default()).is_err());
    }

    /// The resolved git dirs must be as untouchable as `.git`: the policy
    /// never matches paths under them (even under the whole-repo `.`), and
    /// the walker prunes them. A `--separate-git-dir` layout puts them
    /// inside the worktree under an arbitrary name (2026-07 audit).
    #[test]
    fn test_protected_dirs_never_matched_and_pruned() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dunce::canonicalize(dir.path()).unwrap();
        std::fs::create_dir_all(root.join("meta")).unwrap();
        std::fs::write(root.join("meta/HEAD"), b"ref: refs/heads/main").unwrap();
        std::fs::create_dir_all(root.join("docs")).unwrap();
        std::fs::write(root.join("docs/a.txt"), b"x").unwrap();
        let protected = ProtectedDirs::new(vec![root.join("meta")], &root);

        // Policy matching: protected paths never match, not even under `.`.
        let policy = CryptPolicy::try_new(&["meta", "docs"], &protected).unwrap();
        assert!(!policy.matches(Path::new("meta/HEAD")));
        assert!(policy.matches(Path::new("docs/a.txt")));
        let whole = CryptPolicy::try_new(&["."], &protected).unwrap();
        assert!(!whole.matches(Path::new("meta/config")));
        assert!(whole.matches(Path::new("docs/a.txt")));

        // Walking prunes the protected dir even with the whole repo as root.
        let files = list_files(["."], &root, &protected).unwrap();
        assert!(files.iter().any(|f| f.ends_with("docs/a.txt")));
        assert!(
            !files.iter().any(|f| f.ends_with("meta/HEAD")),
            "the resolved git dir must be pruned from the walk: {files:?}"
        );

        // Target validation rejects it by canonical path, whatever its name.
        let err =
            validate_target_root(Path::new("meta/HEAD"), &root, &root, &protected).unwrap_err();
        assert!(matches!(err, Error::ProtectedPath(_)), "got {err:?}");
        assert!(validate_target_root(Path::new("docs/a.txt"), &root, &root, &protected).is_ok());
    }

    /// The policy builder and target resolution share one lexical rule:
    /// `./x`, `x/` and `x` are the same entry; `..` and absolute roots are
    /// hard errors everywhere (A-01).
    #[test]
    fn test_crypt_policy_try_new_normalizes_and_rejects() {
        let policy = CryptPolicy::try_new(
            &["./secret.txt", "secret.txt/", "docs"],
            &ProtectedDirs::default(),
        )
        .unwrap();
        assert!(policy.matches(Path::new("secret.txt")));
        assert!(policy.matches(Path::new("docs/a.txt")));
        assert!(!policy.matches(Path::new("docs2/a.txt")));

        let whole = CryptPolicy::try_new(&["."], &ProtectedDirs::default()).unwrap();
        assert!(whole.matches(Path::new("anything/at.all")));

        for bad in ["d/../secret.txt", "../escape", "/abs/path", "d/../../x"] {
            assert!(
                CryptPolicy::try_new(&[bad], &ProtectedDirs::default()).is_err(),
                "{bad:?} must be a hard error, not a silent skip"
            );
        }
    }

    /// The sweep matches only the full generated name shapes — never a user
    /// file that merely shares the prefix, and never an ambiguous legacy
    /// shape either (A-04): indistinguishable means "never auto-delete".
    #[test]
    fn test_generated_name_patterns() {
        assert!(is_generated_temp_name(".git-se-tmp.a1b2c3d4e5f6g7h8"));
        assert!(is_generated_temp_name(".git-se-tmp.XY19qZ77ab02CD34"));
        assert!(!is_generated_temp_name(".git-se-tmp.ABC123")); // legacy 6-char shape
        assert!(!is_generated_temp_name(".git-se-tmp.notes")); // user file
        assert!(!is_generated_temp_name(".git-se-tmp.keep")); // user file
        assert!(!is_generated_temp_name(".git-se-tmp.has space!"));
        assert!(!is_generated_temp_name(".git-se-tmp.a1b2c3d4e5f6g7h8extra"));

        assert!(is_generated_backup_name(
            ".git-se-bak.0123456789abcdef0123456789abcdef.0"
        ));
        assert!(is_generated_backup_name(
            ".git-se-bak.abcdef0123456789abcdef0123456789.13"
        ));
        // Legacy/previous-version shapes are ambiguous with user files and
        // must NOT be collected automatically.
        assert!(!is_generated_backup_name(".git-se-bak.0"));
        assert!(!is_generated_backup_name(".git-se-bak.2024"));
        assert!(!is_generated_backup_name(".git-se-bak.01234567.0"));
        assert!(!is_generated_backup_name(".git-se-bak.data")); // user file
        assert!(!is_generated_backup_name(".git-se-bak.xyz.0"));
        assert!(!is_generated_backup_name(
            ".git-se-bak.0123456789abcdef0123456789abcdef."
        ));
    }

    /// The exclude merge must preserve bytes it cannot decode — a non-UTF-8
    /// pathspec used to be erased wholesale.
    #[cfg(unix)]
    #[test]
    fn test_exclude_temp_files_preserves_non_utf8() {
        let dir = tempfile::TempDir::new().unwrap();
        let info = dir.path().join("info");
        std::fs::create_dir_all(&info).unwrap();
        let exclude = info.join("exclude");
        let original = b"\xffKEEP\n".as_slice();
        std::fs::write(&exclude, original).unwrap();

        exclude_temp_files(dir.path());

        let after = std::fs::read(&exclude).unwrap();
        assert!(
            after.starts_with(original),
            "original bytes must survive: {after:?}"
        );
        assert!(
            after
                .windows(TEMP_PREFIX.len())
                .any(|w| w == TEMP_PREFIX.as_bytes()),
            "the git-se rules must be appended: {after:?}"
        );
    }

    /// Regression (2026-07 audit): the exclude update must never clobber what
    /// it cannot read. An unreadable `info/exclude` (here: a directory at its
    /// path) used to be treated as "empty", and the merge then replaced it
    /// with a file containing only git-se's rules.
    #[test]
    fn test_exclude_temp_files_never_clobbers_unreadable_exclude() {
        let dir = tempfile::TempDir::new().unwrap();
        let exclude = dir.path().join("info").join("exclude");
        std::fs::create_dir_all(&exclude).unwrap(); // a DIRECTORY at the file's path

        exclude_temp_files(dir.path());
        assert!(
            exclude.is_dir(),
            "an unreadable exclude must be left exactly as it was"
        );
    }

    /// `resolve_target_files` applies the same lexical rule to config
    /// entries: `d/../x` must not walk `x` (A-01).
    #[test]
    fn test_resolve_target_files_rejects_non_relative_config_entry() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path();
        std::fs::create_dir(root.join("d")).unwrap();
        std::fs::write(root.join("secret.txt"), b"x").unwrap();

        let result = resolve_target_files(
            &[],
            &["d/../secret.txt".to_string()],
            root,
            &ProtectedDirs::default(),
        );
        assert!(
            matches!(result, Err(Error::Config(_))),
            "expected Error::Config, got {result:?}"
        );
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
            list_files(
                [".gitignore"],
                Path::new(".").absolutize().unwrap(),
                &ProtectedDirs::default()
            )
            .unwrap(),
            vec![Path::new(".gitignore").absolutize().unwrap()]
        );
        assert_eq!(
            list_files(
                ["lib.rs"],
                Path::new("src").absolutize().unwrap(),
                &ProtectedDirs::default()
            )
            .unwrap(),
            vec![Path::new("src/lib.rs").absolutize().unwrap()]
        );
    }
}
