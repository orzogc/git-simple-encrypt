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

    /// A directory inside the worktree has the SHAPE of a git dir (`HEAD` +
    /// `objects/` + `refs/`) but cannot be confirmed as one: it lacks the
    /// `config` evidence every git-created git dir carries, or the
    /// repository itself tracks files beneath it — in which case it may be
    /// ordinary, allowlisted data. Git happily tracks HEAD/objects/refs-shaped
    /// contents, so shape alone can never be the verdict: silently protecting
    /// such a directory would hide tracked plaintext from the crypt list
    /// (and from `check --staged`), while silently encrypting it could
    /// destroy a repository. Refusing to guess (2026-07 audit).
    #[error(
        "{0} looks like a git directory, but {1} — refusing to guess: if it is a nested \
         repository, move it out of the worktree (or restore its `config`); if it is ordinary \
         data, rename it so it no longer has the HEAD + objects/ + refs/ shape"
    )]
    AmbiguousGitDir(PathBuf, &'static str),

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
         migrate it to this password with `git-se p`, decrypt it with its own password first, \
         or remove it from the crypt list"
    )]
    ForeignCiphertext(PathBuf),

    /// A per-file failure inside a repo-wide batch operation (encrypt,
    /// decrypt, password change). The source keeps its concrete kind
    /// ([`Error::ForeignCiphertext`], [`Error::Io`], [`Error::DecryptFailed`],
    /// ...), so library callers can match through the chain instead of
    /// parsing a flattened string.
    #[error("failed to {action} {}: {source}", .path.display())]
    BatchFile {
        /// The operation being performed, for the message.
        action: &'static str,
        /// The file that failed.
        path: PathBuf,
        /// The concrete failure.
        #[source]
        source: Box<Self>,
    },

    /// Fast decrypt pre-check failed: the password cannot decrypt the first
    /// chunk of an encrypted file (wrong password or corrupted data).
    #[error("password pre-check failed on {0}: wrong password or corrupted file")]
    PasswordCheckFailed(PathBuf),

    /// Verifying the password against `HEAD` exceeded the Argon2 budget: too
    /// many committed anchors with distinct salts (a cloned repository can
    /// contain forged anchors that each cost one expensive derivation). The
    /// password is neither confirmed nor rejected — failing closed instead of
    /// burning unbounded CPU or guessing.
    #[error(
        "cannot verify the password against HEAD within a bounded cost: more than {0} committed \
         encrypted anchors with distinct salts (possible forged-anchor CPU DoS). The password is \
         neither confirmed nor rejected; if you are certain it is correct, re-run with \
         --allow-password-change — or, for a history that legitimately has that many encryption \
         batches, raise the budget explicitly via GIT_SE_HEAD_ANCHOR_BUDGET"
    )]
    PasswordVerificationIndeterminate(usize),

    /// A public batch call mapped two sources to the same destination, or a
    /// destination onto another source's path. Parallel writes would race
    /// and silently keep only one result — while every operation reports
    /// success (2026-07 audit).
    #[error(
        "batch destination conflict at {0}: destinations must be distinct and must not collide \
         with another source's path (mapping a file onto itself is fine); fix the mapper"
    )]
    BatchDestinationConflict(PathBuf),

    /// The working-tree target files carry more distinct salts than the
    /// Argon2 budget allows. Every distinct salt costs one expensive
    /// derivation before the file can be authenticated, and a hostile
    /// repository can plant hundreds of small forged encrypted files — no
    /// password needed — to multiply that cost without bound. Failing closed
    /// BEFORE any derivation runs, same policy as the HEAD anchor budget.
    #[error(
        "refusing to process more than {0} distinct salts among the target files (each costs one \
         Argon2 derivation; a hostile repository can plant forged encrypted files to multiply \
         that cost without bound). If this repository legitimately has that many encryption \
         batches, raise the budget explicitly via GIT_SE_SALT_BUDGET"
    )]
    SaltBudgetExceeded(usize),

    /// A previous transaction's recovery did not restore every destination.
    /// Running any command on the partially recovered repository would start
    /// from a mixed state, so [`crate::Repo::open`] refuses until the journal
    /// is resolved manually.
    #[error(
        "a previous git-se transaction could not be fully recovered: {0} destination(s) are \
         still unrestored. Restore them manually from the backups listed in the transaction \
         journal at {1} (each pair is `destination`, `backup`), verify the results, then remove \
         that journal — refusing to run on a partially recovered repository"
    )]
    RecoveryIncomplete(usize, PathBuf),

    /// The transaction journal could not be parsed (unknown version or a
    /// truncated record). It is kept untouched; guessing at its contents
    /// could rename the wrong files, so everything stops until a human looks.
    #[error(
        "the transaction journal at {0} is corrupt (unknown version or truncated); refusing to \
         run — inspect it manually, restore any unrestored destinations from their backups, \
         then remove the journal"
    )]
    JournalCorrupt(PathBuf),

    /// The transaction journal exists but cannot be read (an I/O error other
    /// than "not found": permissions, a directory at that path, ...). Only a
    /// genuinely ABSENT journal means "no interrupted transaction" — anything
    /// else must fail closed, or a command could run on a half-recovered tree
    /// and the startup sweep could delete the backups that are the last
    /// recovery material.
    #[error(
        "the transaction journal at {0} exists but could not be read ({1}); refusing to run — \
         fix the cause (permissions, or a directory at that path), then re-run any git-se \
         command to retry recovery"
    )]
    JournalUnreadable(PathBuf, String),

    /// Every destination was restored, but the transaction journal itself
    /// could not be removed (or its removal could not be made durable). The
    /// journal and all backups were kept — deleting the backups while the
    /// journal lives would strand the repository in a permanent
    /// missing-backup anomaly.
    #[error(
        "recovery restored every file, but the transaction journal at {0} could not be removed \
         (or its removal could not be made durable); fix the cause and re-run any git-se \
         command, or remove that journal and the remaining .git-se-bak.* backups manually"
    )]
    JournalLeftover(PathBuf),

    /// The operation committed successfully, but some backup files (which
    /// hold the pre-operation content — **plaintext** after an encrypt, and
    /// possibly plaintext for members that were plaintext before a password
    /// change) could not be removed. The repository is in its final state;
    /// only the leftover backups need manual deletion.
    #[error(
        "the operation committed successfully, but {} backup file(s) could not be removed — they \
         hold the pre-operation content (PLAINTEXT after an encrypt or for files that were \
         plaintext before a password change); remove them manually: {}",
        .0.len(),
        .0.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ")
    )]
    BackupCleanupFailed(Vec<PathBuf>),

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

    /// A decrypted chunk's stored nonce does not match the nonce derived
    /// from its AAD and plaintext. AEAD already authenticated the chunk;
    /// this enforces the v5 derivation contract at the decryption boundary,
    /// so ciphertext from a non-conformant producer (e.g. the pre-release
    /// v4 development format) is rejected even when it authenticates.
    #[error(
        "nonce derivation mismatch: the stored nonce does not equal \
         Blake3_keyed(Key_MAC, AAD || plaintext) — this file was produced by a non-conformant \
         or incompatible encryptor"
    )]
    NonceDerivationMismatch,

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
