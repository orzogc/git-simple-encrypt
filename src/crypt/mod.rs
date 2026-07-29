//! The core of this program. Encrypt/decrypt, compress/decompress files.
//!
//! # Module Structure
//!
//! | Module | Contents |
//! |---|---|
//! | `header` | Constants (`MAGIC`, `VERSION`, `SALT_LEN`, …) and [`FileHeader`] |
//! | `key` | Key derivation (Argon2, [`Password`]/[`DerivedKey`], nonce derivation) + key cache |
//! | `stream` | Streaming `Read → Write` encrypt/decrypt primitives |
//! | `file` | File-to-file encrypt/decrypt with atomic writes & metadata preservation |
//! | `batch` | Parallel batch operations with shared key cache |
//! | `repo` | Repository-level encrypt/decrypt with salt cache integration |
//!
//! See the module-level docs of each submodule for details.
//!
//! # Nonce Derivation (Bound to the Entire AEAD Input)
//!
//! Per-chunk nonces are derived from the chunk's **entire AEAD input** — its
//! fully assembled AAD (header, chain link, chunk index, last-chunk flag)
//! plus its plaintext — using keyed Blake3:
//!
//! 1. A random 16-byte `File_ID` is generated once per file and stored in the
//!    header. Via the AAD it ensures that even if two different files have
//!    identical plaintext at chunk 0, they produce different nonces and
//!    ciphertexts.
//! 2. The Argon2-derived master key is split via `blake3::derive_key` into
//!    `Key_ENC` (for XChaCha20-Poly1305 encryption) and `Key_MAC` (for nonce
//!    generation).
//! 3. For each chunk `i`: `Nonce_i = Blake3_keyed(Key_MAC, AAD_i || M_i)[0..24]`
//! 4. The 24-byte nonce is stored in plaintext at the head of each encrypted
//!    chunk.
//!
//! The governing invariant: except with the negligible probability of a
//! PRF collision (the nonce is a 192-bit truncation of a 256-bit keyed
//! Blake3 output), a repeated nonce implies a repeated (AAD, plaintext)
//! pair — a byte-identical re-encryption of identical input, which is the
//! intended deterministic guarantee and is cryptographically harmless. ChaCha20-Poly1305 derives its Poly1305 one-time key from
//! (key, nonce), so a nonce that ever authenticated two *different* AADs
//! would void the tag's unforgeability for that chunk. Deriving the nonce
//! from the plaintext alone broke exactly that under v4's chain: an edit to
//! an early chunk changes every later chunk's AAD (the chain carries the
//! predecessor's tag) while an unchanged tail chunk kept its nonce. Binding
//! the nonce to the whole AAD closes the hole — any prefix change
//! re-randomizes every later chunk's nonce, and the two mechanisms (nonce
//! derivation and the AAD chain) reinforce each other instead of resting on
//! independent assumptions.
//!
//! # Authenticated Additional Data (AAD) — v4 chain, v5 nonce binding
//!
//! Each chunk's AAD binds the ciphertext to the full file header **and to
//! its predecessor's Poly1305 tag**:
//!
//! ```text
//! AAD_i = HEADER (64B) || tag_{i-1} (16B) || chunk_idx (8B LE) || is_last (1B)  // 89 bytes
//! AAD_0 uses file_id (16B) as the chain seed instead of a tag.
//! ```
//!
//! Tampering with any header field is detected via Poly1305 authentication
//! failure, and the tag chain defeats **cross-version block replay**: a
//! ciphertext block replayed from an older version of the same file (same
//! salt + `file_id` reused for deterministic re-encryption) breaks the chain
//! at the following chunk, so any splice collapses to a full-file revert —
//! and reverting to a previously valid ciphertext is not a forgery.
//!
//! Each encrypted chunk layout: `[NONCE (24B)] [CIPHERTEXT] [TAG (16B)]`.
//! On decrypt, every chunk's stored nonce is re-verified against the
//! derivation above (after AEAD, on the authenticated plaintext): the v5
//! format enforces the derivation contract at the decryption boundary, and
//! the pre-release v4 development format is rejected outright by the
//! version byte.
//!
//! # Key Semantics (Password vs. Derived Key) — read before use!
//!
//! The API is intentionally asymmetric:
//!
//! - **Encryption** entry points ([`encrypt_file`], [`encrypt_file_to`],
//!   [`encrypt_into`]) take an **Argon2-derived key** (`&[u8; 32]`, see
//!   [`derive_key`]), because batch encryption derives once per salt and
//!   reuses the result across files (Argon2 is expensive).
//! - **Decryption** entry points ([`decrypt_file`], [`decrypt_file_to`],
//!   [`decrypt_into`], [`decrypt_file_with_cache`]) take the **raw password**
//!   and run Argon2 internally, using the salt stored in each file's header.
//!
//! The two are distinct newtypes ([`Password`] and [`DerivedKey`]), so the
//! compiler rejects a mix-up outright — passing one where the other is
//! expected is a type error, not a runtime [`crate::Error::DecryptFailed`].
//! Both still need care when *constructing* them: `Password::new` accepts any
//! byte slice, so feeding it an already-derived key compiles.

mod batch;
mod file;
mod header;
mod key;
mod repo;
mod stream;
mod txn;

pub use batch::{BatchSummary, decrypt_files_to, encrypt_files_to};
pub use file::{
    PreparedWrite, decrypt_file, decrypt_file_to, decrypt_file_with_cache, encrypt_file,
    encrypt_file_to, prepare_decrypt_file, prepare_encrypt_file, prepare_reencrypt_file,
};
pub use header::{
    FILE_ID_LEN, FileHeader, HEADER_LEN, HeaderProbe, MAGIC, MIN_ENCRYPTED_LEN, MalformedReason,
    NONCE_LEN, SALT_LEN, VERSION, framing_is_plausible, is_encrypted_header, is_encrypted_version,
    probe_header,
};
pub use key::{DerivedKey, Password, derive_key};
pub use repo::{
    HeadPasswordCheck, cache_key, change_password, decrypt_repo, encrypt_repo, precheck_password,
    verify_password_against_head,
};
pub use stream::{decrypt_into, encrypt_into};
pub(crate) use txn::journal_path;
pub use txn::{Recovery, RepoLock, acquire_repo_lock, recover as recover_interrupted_commit};

#[cfg(test)]
mod tests;
