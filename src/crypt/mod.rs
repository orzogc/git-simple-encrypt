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
//! # Nonce Derivation (Content-Based with File ID)
//!
//! Per-chunk nonces are derived from the file's random `File_ID` and the
//! chunk's own plaintext content using keyed Blake3:
//!
//! 1. A random 16-byte `File_ID` is generated once per file and stored in the
//!    header. This ensures that even if two different files have identical
//!    plaintext at chunk 0, they produce different nonces and ciphertexts.
//! 2. The Argon2-derived master key is split via `blake3::derive_key` into
//!    `Key_ENC` (for XChaCha20-Poly1305 encryption) and `Key_MAC` (for nonce
//!    generation).
//! 3. For each chunk `i`: `Nonce_i = Blake3_keyed(Key_MAC, File_ID || M_i ||
//!    chunk_idx_le)[0..24]`
//! 4. The 24-byte nonce is stored in plaintext at the head of each encrypted
//!    chunk.
//!
//! Different plaintext always produces a different nonce (within the same
//! file). The `File_ID` ensures cross-file uniqueness. The chunk index prevents
//! reordering attacks on identical 64 KB blocks. Integrity *across* versions
//! of a file is enforced by the AAD chain (below), not by the nonce.
//!
//! # Authenticated Additional Data (AAD) — v4 chain
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
//! Each encrypted chunk layout: `[NONCE (24B)] [CIPHERTEXT] [TAG (16B)]`
//!
//! # Key Semantics (Password vs. Derived Key) — read before use!
//!
//! The API is intentionally asymmetric, and getting it wrong only fails at
//! runtime:
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

pub use batch::{BatchSummary, decrypt_files_to, encrypt_files_to};
pub use file::{
    PreparedWrite, decrypt_file, decrypt_file_to, decrypt_file_with_cache, encrypt_file,
    encrypt_file_to, prepare_decrypt_file, prepare_encrypt_file, prepare_reencrypt_file,
};
pub use header::{
    FILE_ID_LEN, FileHeader, HEADER_LEN, HeaderProbe, MAGIC, MIN_ENCRYPTED_LEN, MalformedReason,
    NONCE_LEN, SALT_LEN, VERSION, is_encrypted_header, is_encrypted_version, probe_header,
};
pub use key::{DerivedKey, Password, derive_key};
pub use repo::{
    HeadPasswordCheck, cache_key, change_password, decrypt_repo, encrypt_repo, precheck_password,
    verify_password_against_head,
};
pub use stream::{decrypt_into, encrypt_into};

#[cfg(test)]
mod tests;
