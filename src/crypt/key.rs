use std::sync::{Arc, OnceLock};

use argon2::Argon2;
use dashmap::DashMap;
use zeroize::Zeroizing;

use crate::{
    crypt::header::{AAD_LEN, NONCE_LEN, SALT_LEN},
    error::{Error, Result},
};

/// The raw master password — input to Argon2 and to every **decryption**
/// entry point.
///
/// Deliberately a distinct type from [`DerivedKey`] (M-05): the two secrets
/// are both byte slices, and passing one where the other is expected used to
/// compile fine and fail only at runtime. Never persisted anywhere.
#[derive(Clone, Copy)]
pub struct Password<'a>(&'a [u8]);

impl<'a> Password<'a> {
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(self) -> &'a [u8] {
        self.0
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Password<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Password([REDACTED])")
    }
}

/// The 32-byte Argon2 output — input to every **encryption** entry point.
///
/// Scrubbed from memory on drop. See "Key Semantics" in the
/// [module docs](crate::crypt).
#[derive(Clone)]
pub struct DerivedKey(Zeroizing<[u8; 32]>);

impl DerivedKey {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DerivedKey([REDACTED])")
    }
}

impl From<[u8; 32]> for DerivedKey {
    fn from(key: [u8; 32]) -> Self {
        Self(Zeroizing::new(key))
    }
}

/// Derive the 32-byte master key from a password and a 16-byte salt (Argon2id).
///
/// The single funnel for every raw-password API, so the empty-password
/// rejection lives here: the CLI layer checks it too, but a library caller
/// must not be able to create empty-password ciphertext by accident.
pub fn derive_key(password: Password<'_>, salt: &[u8]) -> Result<DerivedKey> {
    if password.is_empty() {
        return Err(Error::EmptyKey);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut *key)
        .map_err(|e| Error::Argon2(e.to_string()))?;
    Ok(DerivedKey(key))
}

pub(super) fn split_keys(master_key: &DerivedKey) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let key_enc = blake3::derive_key("git-simple-encrypt-enc", master_key.as_bytes());
    let key_mac = blake3::derive_key("git-simple-encrypt-mac", master_key.as_bytes());
    (Zeroizing::new(key_enc), Zeroizing::new(key_mac))
}

/// Derive a chunk's nonce from its **entire AEAD input**: the fully assembled
/// AAD (header, chain link, chunk index, last-chunk flag) plus the plaintext.
///
/// The governing invariant: a repeated nonce implies a repeated
/// (AAD, plaintext) pair — i.e. a byte-identical re-encryption of identical
/// input, which is the intended deterministic guarantee and cryptographically
/// harmless. Deriving from the plaintext alone (pre-fix) broke that invariant
/// for v4: an edit to an early chunk changes every later chunk's AAD (the
/// chain carries the predecessor's tag) while an unchanged tail chunk kept
/// its nonce, so one (key, nonce) pair ended up authenticating two different
/// AADs — a Poly1305 one-time-key reuse that voided the chain's anti-splice
/// guarantee. Binding the nonce to the whole AAD closes it: any prefix change
/// re-randomizes every later chunk's nonce.
pub(super) fn derive_nonce(
    key_mac: &[u8; 32],
    aad: &[u8; AAD_LEN],
    plaintext: &[u8],
) -> [u8; NONCE_LEN] {
    let mut hasher = blake3::Hasher::new_keyed(key_mac);
    hasher.update(aad);
    hasher.update(plaintext);
    let hash = hasher.finalize();
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&hash.as_bytes()[..NONCE_LEN]);
    nonce
}

pub(super) type KeyCache = DashMap<[u8; SALT_LEN], Arc<OnceLock<Result<DerivedKey, String>>>>;

pub(super) fn get_or_derive_key(
    key_cache: &KeyCache,
    password: Password<'_>,
    salt: &[u8; SALT_LEN],
) -> Result<DerivedKey> {
    let lock = {
        let guard = key_cache
            .entry(*salt)
            .or_insert_with(|| Arc::new(OnceLock::new()));
        Arc::clone(&*guard)
    };

    match lock.get_or_init(|| derive_key(password, salt).map_err(|e| e.to_string())) {
        Ok(key) => Ok(key.clone()),
        Err(msg) => Err(Error::Argon2(msg.clone())),
    }
}
