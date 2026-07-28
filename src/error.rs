//! Crate-wide error type.
//!
//! Library code returns [`Error`] (typed via `thiserror`) so downstream users
//! can match on error kinds. Internal helpers use other dedicated variants;
//! [`Error::Other`] serves as a catch-all for opaque error messages from the
//! binary layer (git config, path absolutization, etc.).

use std::path::PathBuf;

use thiserror::Error;

/// The error type returned by all public library functions.
#[derive(Debug, Error)]
pub enum Error {
    /// `repo` argument was not an absolute path (lib callers must absolutize).
    #[error("repository path must be absolute: {0}")]
    RepoPathNotAbsolute(PathBuf),

    /// Repository directory does not exist.
    #[error("repo not found: {0}")]
    RepoNotFound(PathBuf),

    /// Repository path is not a directory.
    #[error("not a directory: {0}")]
    NotADirectory(PathBuf),

    /// Path supplied for the crypt list does not exist on disk.
    #[error("file or directory does not exist: {0}")]
    PathNotExist(PathBuf),

    /// Expected a repo-relative path but got an absolute one.
    #[error("expected repo-relative path, got absolute: {0}")]
    PathNotRelative(PathBuf),

    /// Path is not valid UTF-8 and therefore cannot be stored in the TOML
    /// crypt list without corrupting it.
    #[error(
        "path is not valid UTF-8 and cannot be added to the crypt list: {0}; \
         rename the file to a UTF-8 name first"
    )]
    NonUtf8Path(PathBuf),

    /// Path escapes the repository root (e.g. `../outside.txt`).
    #[error("path escapes the repository: {0}")]
    PathEscapesRepo(PathBuf),

    /// A target is reached through a symlink inside the repository. Where such
    /// a link points can change between validation and use, so it is refused
    /// rather than resolved.
    #[error(
        "refusing to operate through the symlink {0}: where it points could change between \
         the check and the write. Target the real path instead"
    )]
    SymlinkedTarget(PathBuf),

    /// Path points at git internals or git-se's own config file; encrypting
    /// it would break the repository or the tool itself.
    #[error("refusing to add protected path (git internals or git-se config): {0}")]
    ProtectedPath(PathBuf),

    /// No working `git` binary could be run. Every repository boundary
    /// git-se enforces (worktree top level, git dir, common dir) is answered
    /// by git plumbing, and guessing it once let a detached git dir's
    /// contents get encrypted — so this is a hard error, not a fallback.
    #[error(
        "could not run `git` ({0}); git-se requires a working git binary to establish \
         repository boundaries"
    )]
    GitUnavailable(String),

    /// Another git-se process holds this repository's lock. Running now
    /// would let two processes mistake each other's live transaction for a
    /// crashed one and interfere with its files.
    #[error(
        "another git-se process is running on this repository (lock: {0}); re-run after it \
         finishes"
    )]
    RepoLocked(PathBuf),

    /// The requested repository root lies inside a git dir. Treating it as a
    /// worktree would expose refs, objects and config as ordinary files.
    #[error("refusing to use a path inside a git directory as a repository root: {0}")]
    PathInsideGitDir(PathBuf),

    /// The two interactively entered passwords did not match.
    #[error("passwords do not match")]
    PasswordMismatch,

    /// The entered password differs from the one used for the encrypted
    /// files committed in `HEAD`. Payload: how many target files are still
    /// encrypted with the previous password.
    #[error(
        "the entered password differs from the one used for committed encrypted files \
             ({0} target files still encrypted with it); if this is an intentional password \
             change, re-run with --allow-password-change"
    )]
    PasswordChanged(usize),

    /// A target file is already encrypted, but not with the password given.
    /// Skipping it on format alone would leave it silently unreadable.
    #[error(
        "{0} is already encrypted, but not with this password (or it has been tampered with); \
         decrypt it with its own password first, or pass --allow-password-change to leave \
         such files untouched"
    )]
    ForeignCiphertext(PathBuf),

    /// Fast decrypt pre-check failed: the password cannot decrypt the first
    /// chunk of an encrypted file (wrong password or corrupted data).
    #[error("password pre-check failed on {0}: wrong password or corrupted file")]
    PasswordCheckFailed(PathBuf),

    /// The user chose to abort at an interactive prompt.
    #[error("aborted by user")]
    Aborted,

    /// Master key/password is empty.
    #[error("key must not be empty")]
    EmptyKey,

    /// User entered an empty password interactively.
    #[error("password must not be empty")]
    EmptyPassword,

    /// Operation had no target files to act on.
    #[error("no file to {0}")]
    NoFile(&'static str),

    /// File does not start with the `GITSE` magic / supported version.
    #[error("invalid magic bytes")]
    InvalidMagic,

    /// Header advertises an unsupported format version.
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u8),

    /// Header advertises an unsupported encryption algorithm.
    #[error("unsupported encryption algorithm: {0}")]
    UnsupportedAlgo(u8),

    /// Header sets flag bits this version does not know. The body cannot be
    /// interpreted safely, so the file is neither ciphertext nor plaintext.
    #[error("unknown header flag bits set: {0:#04x}")]
    UnknownHeaderFlags(u8),

    /// Header's reserved field is not zeroed as the format requires.
    #[error("header reserved field is not zero")]
    ReservedNotZero,

    /// A file carries the `GITSE` magic but is not a valid encrypted file.
    /// Acting on it either way risks data loss, so it is refused outright.
    #[error(
        "{0} looks like an encrypted file but is malformed ({1}); \
         inspect it manually — refusing to encrypt (would destroy ciphertext) \
         or to treat it as encrypted (would leak plaintext)"
    )]
    MalformedEncryptedFile(PathBuf, crate::crypt::MalformedReason),

    /// XChaCha20-Poly1305 encryption failure.
    #[error("encryption failed: {0}")]
    EncryptFailed(String),

    /// XChaCha20-Poly1305 decryption failure (wrong password, corrupt or
    /// tampered data are all reported identically by AEAD).
    #[error("decryption failed (wrong password, corrupt, or tampered data): {0}")]
    DecryptFailed(String),

    /// Argon2 key derivation failure.
    #[error("Argon2 key derivation failed: {0}")]
    Argon2(String),

    /// Encrypted chunk is missing its ciphertext.
    #[error("truncated chunk: nonce present but no ciphertext follows")]
    TruncatedChunk,

    /// Encrypted file ended without a final chunk.
    #[error("file truncation detected! the ciphertext is incomplete")]
    FileTruncated,

    /// Atomic temp-file persist failed.
    #[error("failed to persist atomic write to {0}: {1}")]
    AtomicPersist(PathBuf, String),

    /// Underlying `git` invocation failed.
    #[error("git command failed: {0}")]
    Git(String),

    /// A pre-commit hook already exists at the target path.
    #[error("a pre-commit hook already exists at {0}; remove it manually before installing")]
    HookExists(PathBuf),

    /// `check` found unencrypted files. The count is `(unencrypted, total)`.
    #[error("{0} out of {1} files are not encrypted")]
    FilesNotEncrypted(usize, usize),

    /// Config file parse/serialize error.
    #[error("config error: {0}")]
    Config(String),

    /// Generic I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Rkyv (de)serialization failure for the salt cache.
    #[error("salt cache serialization error: {0}")]
    SaltCache(String),

    /// Anything else — an opaque error message.
    #[error("{0}")]
    Other(String),
}

/// Convenience alias used throughout the crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;
