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
    crypt::{HEADER_LEN, MAGIC, is_encrypted_version},
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
) -> Vec<PathBuf> {
    let mut paths_iter = paths.into_iter();
    let cwd = cwd.as_ref();

    let mut builder = if let Some(first_path) = paths_iter.next() {
        debug_assert!(first_path.as_ref().is_relative());
        WalkBuilder::new(lexical_normalize(&cwd.join(first_path)))
    } else {
        return Vec::new();
    };

    for p in paths_iter {
        debug_assert!(p.as_ref().is_relative());
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
            if let Ok(entry) = result
                && let Some(file_type) = entry.file_type()
                && file_type.is_file()
            {
                let _ = tx.send(entry.into_path());
            }
            WalkState::Continue
        })
    });

    drop(tx);
    rx.into_iter().collect()
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

/// Check whether a single file has a valid GITSE encrypted header.
/// Returns an error if the file cannot be read (IO error).
pub fn is_file_encrypted(path: &Path) -> Result<bool> {
    let mut file = fs::File::open(path)?;
    let mut header_bytes = [0u8; HEADER_LEN];
    // A single `read()` may return short; use `read_exact` and treat
    // unexpected EOF (file smaller than the header) as "not encrypted".
    match file.read_exact(&mut header_bytes) {
        Ok(()) => Ok(&header_bytes[0..5] == MAGIC && is_encrypted_version(header_bytes[5])),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(e.into()),
    }
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
    use path_absolutize::Absolutize as _;
    for entry in paths.iter().map(PathBuf::as_path).chain(
        crypt_list
            .iter()
            .map(String::as_str)
            .map(std::convert::AsRef::<Path>::as_ref),
    ) {
        let abs = entry
            .absolutize_from(repo_path)
            .map_err(|e| Error::Other(format!("path absolutize failed: {e}")))?;
        if !abs.starts_with(repo_path) {
            return Err(Error::PathEscapesRepo(abs.into_owned()));
        }
    }

    let mut files = if paths.is_empty() {
        list_files(crypt_list.iter(), repo_path)
    } else {
        list_files(paths, repo_path)
    };
    files.sort_unstable();
    files.dedup();
    Ok(files)
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use path_absolutize::Absolutize as _;

    use super::*;

    #[test]
    fn test_list_files() {
        let paths = vec!["docs", ".gitignore", "src", "some_thing_not_exist"]
            .into_iter()
            .map(PathBuf::from);
        let res = list_files(paths, ".")
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

    #[test]
    fn test_cwd() {
        assert_eq!(
            list_files([".gitignore"], Path::new(".").absolutize().unwrap()),
            vec![Path::new(".gitignore").absolutize().unwrap()]
        );
        assert_eq!(
            list_files(["lib.rs"], Path::new("src").absolutize().unwrap()),
            vec![Path::new("src/lib.rs").absolutize().unwrap()]
        );
    }
}
