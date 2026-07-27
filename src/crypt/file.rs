use std::{
    fs,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

use log::{debug, warn};
use tempfile::NamedTempFile;

use crate::{
    crypt::{
        header::{
            FILE_ID_LEN, FileHeader, HEADER_LEN, HeaderProbe, MIN_ENCRYPTED_LEN, MalformedReason,
            SALT_LEN, probe_header,
        },
        key::{DerivedKey, KeyCache, Password, get_or_derive_key, split_keys},
        stream::{decrypt_body, encrypt_into, new_cipher},
    },
    error::{Error, Result},
    salt_cache::{CacheRef, CachedEntry},
};

/// Format-probe an already-open file and rewind it.
///
/// Every encrypt/decrypt entry point funnels through here so they all reach
/// the same verdict (M-01): the skip decision on encrypt and the "is this
/// encrypted" decision on decrypt can never disagree.
pub(super) fn probe_and_rewind(file: &mut fs::File, path: &Path) -> Result<HeaderProbe> {
    let mut buf = Vec::with_capacity(MIN_ENCRYPTED_LEN);
    (&mut *file)
        .take(MIN_ENCRYPTED_LEN as u64)
        .read_to_end(&mut buf)?;
    file.seek(SeekFrom::Start(0))?;
    let probe = probe_header(&buf);
    if let HeaderProbe::Malformed(reason) = probe {
        return Err(match reason {
            // A valid header with a cut-off body is plain truncation; say so
            // rather than sending the user hunting for a corrupt header.
            MalformedReason::NoCompleteChunk => Error::FileTruncated,
            other => Error::MalformedEncryptedFile(path.to_path_buf(), other),
        });
    }
    Ok(probe)
}

/// Persist a `NamedTempFile` to `dst` atomically, optionally copying metadata.
///
/// The temp file is `fsync`ed before the rename and the destination directory
/// is synced afterwards (best-effort), so a crash mid-operation cannot leave
/// a renamed but empty/partial file at `dst`.
pub(super) fn persist_temp_file(
    temp_file: NamedTempFile,
    dst: &Path,
    metadata_source: Option<&Path>,
) -> Result<()> {
    if let Some(src) = metadata_source
        && let Err(e) = copy_metadata::copy_metadata(src, temp_file.path())
    {
        warn!("Could not copy metadata from {}: {}", src.display(), e);
    }
    temp_file.as_file().sync_all()?;
    temp_file
        .persist(dst)
        .map_err(|e| Error::AtomicPersist(dst.to_path_buf(), e.to_string()))?;
    crate::utils::sync_dir(dst.parent().unwrap_or_else(|| Path::new(".")));
    Ok(())
}

/// A finished replacement file waiting to be renamed into place.
///
/// Phase one of the two-phase commit used by repo-wide operations (H-05):
/// the new content is fully written next to its destination, but nothing is
/// visible yet. Dropping a `PreparedWrite` without committing removes the
/// temp file and leaves the target untouched, which is what makes "all or
/// nothing" possible — a failure on file 7 of 10 must not leave files 1..6
/// converted and 7..10 not.
#[must_use = "a prepared write does nothing until committed"]
pub struct PreparedWrite {
    temp: NamedTempFile,
    dst: std::path::PathBuf,
    /// Where to copy permissions and timestamps from.
    metadata_source: std::path::PathBuf,
    /// The header that was written (encrypt) or read (decrypt).
    pub header: FileHeader,
}

impl PreparedWrite {
    /// Phase two: fsync and rename into place.
    pub fn commit(self) -> Result<()> {
        persist_temp_file(self.temp, &self.dst, Some(&self.metadata_source))
    }

    /// The destination this write will replace.
    #[must_use]
    pub fn destination(&self) -> &Path {
        &self.dst
    }
}

/// Encrypt `src` into a temp file next to `dst`, without committing it.
///
/// `derived_key` is the **Argon2 output** (`&[u8; 32]`), NOT the raw password.
/// Returns `Ok(None)` when `src` is already encrypted.
pub fn prepare_encrypt_file(
    src: &Path,
    dst: &Path,
    derived_key: &DerivedKey,
    salt: [u8; SALT_LEN],
    file_id: Option<[u8; FILE_ID_LEN]>,
    zstd: Option<u8>,
) -> Result<Option<PreparedWrite>> {
    let mut src_file = fs::File::open(src)?;

    // A malformed GITSE-looking file is an error, not a silent skip: it used
    // to be skipped by encrypt yet rejected by `check`, leaving a state the
    // user could not get out of (M-01).
    if probe_and_rewind(&mut src_file, src)? == HeaderProbe::Encrypted {
        warn!("Source file already encrypted, skipping: {}", src.display());
        return Ok(None);
    }

    debug!("Encrypting {} → {}", src.display(), dst.display());

    let dst_parent = dst.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dst_parent)?;
    let mut temp_file = NamedTempFile::new_in(dst_parent)?;

    let header = encrypt_into(
        &mut src_file,
        &mut temp_file,
        derived_key,
        salt,
        file_id,
        zstd,
    )?;

    Ok(Some(PreparedWrite {
        temp: temp_file,
        dst: dst.to_path_buf(),
        metadata_source: src.to_path_buf(),
        header,
    }))
}

/// Encrypt `src` into `dst`.
///
/// `derived_key` is the **Argon2 output** (`&[u8; 32]`), NOT the raw password.
/// See "Key Semantics" in the [module docs](crate::crypt).
pub fn encrypt_file_to(
    src: &Path,
    dst: &Path,
    derived_key: &DerivedKey,
    salt: [u8; SALT_LEN],
    file_id: Option<[u8; FILE_ID_LEN]>,
    zstd: Option<u8>,
) -> Result<Option<FileHeader>> {
    let Some(prepared) = prepare_encrypt_file(src, dst, derived_key, salt, file_id, zstd)? else {
        return Ok(None);
    };
    let header = prepared.header;
    prepared.commit()?;
    Ok(Some(header))
}

/// Decrypt `src` into `dst`.
///
/// `master_key` is the **raw password** (Argon2 is applied internally using
/// the header salt), NOT a derived key. See "Key Semantics" in the
/// [module docs](crate::crypt).
pub fn decrypt_file_to(
    src: &Path,
    dst: &Path,
    master_key: Password<'_>,
) -> Result<Option<FileHeader>> {
    let Some(prepared) = prepare_decrypt_file(src, dst, None, master_key)? else {
        return Ok(None);
    };
    let header = prepared.header;
    prepared.commit()?;
    Ok(Some(header))
}

/// Decrypt `src` into a temp file next to `dst`, without committing it.
///
/// `master_key` is the **raw password**. When `key_cache` is given, Argon2
/// derivation is shared across files with the same salt. Returns `Ok(None)`
/// when `src` is not an encrypted file.
pub fn prepare_decrypt_file(
    src: &Path,
    dst: &Path,
    key_cache: Option<&KeyCache>,
    master_key: Password<'_>,
) -> Result<Option<PreparedWrite>> {
    let mut src_file = fs::File::open(src)?;

    if probe_and_rewind(&mut src_file, src)? != HeaderProbe::Encrypted {
        debug!("File not encrypted, skipping: {}", src.display());
        return Ok(None);
    }

    debug!("Decrypting {} → {}", src.display(), dst.display());

    let mut header_bytes = [0u8; HEADER_LEN];
    src_file.read_exact(&mut header_bytes)?;
    let header = *FileHeader::from_bytes(&header_bytes)?;
    let derived_key = match key_cache {
        Some(cache) => get_or_derive_key(cache, master_key, &header.salt)?,
        None => super::key::derive_key(master_key, &header.salt)?,
    };

    let dst_parent = dst.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dst_parent)?;
    let mut temp_file = NamedTempFile::new_in(dst_parent)?;

    let (key_enc, _) = split_keys(&derived_key);
    let cipher = new_cipher(&key_enc);
    decrypt_body(&mut src_file, &mut temp_file, &cipher, &header)?;

    Ok(Some(PreparedWrite {
        temp: temp_file,
        dst: dst.to_path_buf(),
        metadata_source: src.to_path_buf(),
        header,
    }))
}

/// Encrypt a single file **in place**.
///
/// `derived_key` is the **Argon2 output** (`&[u8; 32]`), NOT the raw password.
pub fn encrypt_file(
    path: &Path,
    derived_key: &DerivedKey,
    salt: &[u8; SALT_LEN],
    file_id: Option<[u8; FILE_ID_LEN]>,
    zstd: Option<u8>,
) -> Result<Option<FileHeader>> {
    encrypt_file_to(path, path, derived_key, *salt, file_id, zstd)
}

/// Decrypt a single file **in place**.
///
/// `master_key` is the **raw password**, NOT a derived key.
pub fn decrypt_file(path: &Path, master_key: Password<'_>) -> Result<()> {
    decrypt_file_to(path, path, master_key).map(|_| ())
}

/// Decrypt a single file with a thread-safe Argon2 key cache and optional
/// salt/`file_id` cache.
///
/// `master_key` is the **raw password**, NOT a derived key. The salt/`file_id`
/// cache entry is recorded only after a fully successful decrypt.
pub fn decrypt_file_with_cache(
    path: &Path,
    key_cache: &KeyCache,
    cache: Option<CacheRef<'_>>,
    master_key: Password<'_>,
) -> Result<()> {
    let Some(prepared) = prepare_decrypt_file(path, path, Some(key_cache), master_key)? else {
        return Ok(());
    };
    let header = prepared.header;
    prepared.commit()?;
    record_salt_cache(cache, &header);
    Ok(())
}

/// Re-encrypt `path` from `old_password` to `new_password` in one step,
/// without committing.
///
/// The plaintext never reaches `path`: it lives only in a temp file that is
/// deleted before this returns. That is what lets a password change be a
/// single transaction (H-05) — the previous "decrypt everything, then encrypt
/// everything" sequence left the whole repo in plaintext whenever the second
/// half failed.
///
/// The original salt and `file_id` are reused so the deterministic
/// re-encryption guarantee still holds; the derived key differs anyway
/// because the password does.
pub fn prepare_reencrypt_file(
    path: &Path,
    old_key_cache: &KeyCache,
    new_key_cache: &KeyCache,
    old_password: Password<'_>,
    new_password: Password<'_>,
    zstd: Option<u8>,
) -> Result<Option<PreparedWrite>> {
    let mut file = fs::File::open(path)?;
    if probe_and_rewind(&mut file, path)? != HeaderProbe::Encrypted {
        debug!("File not encrypted, skipping: {}", path.display());
        return Ok(None);
    }

    let mut header_bytes = [0u8; HEADER_LEN];
    file.read_exact(&mut header_bytes)?;
    let header = *FileHeader::from_bytes(&header_bytes)?;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));

    // Decrypt with the old password into a scratch file that never gets
    // committed and is removed when it drops.
    let mut plain = NamedTempFile::new_in(parent)?;
    {
        let old_key = get_or_derive_key(old_key_cache, old_password, &header.salt)?;
        let (key_enc, _) = split_keys(&old_key);
        decrypt_body(&mut file, &mut plain, &new_cipher(&key_enc), &header)?;
    }
    drop(file);
    plain.as_file_mut().seek(SeekFrom::Start(0))?;

    // Re-encrypt with the new password, same salt and file_id.
    let new_key = get_or_derive_key(new_key_cache, new_password, &header.salt)?;
    let mut temp_file = NamedTempFile::new_in(parent)?;
    let new_header = encrypt_into(
        plain.as_file_mut(),
        &mut temp_file,
        &new_key,
        header.salt,
        Some(header.file_id),
        zstd,
    )?;

    Ok(Some(PreparedWrite {
        temp: temp_file,
        dst: path.to_path_buf(),
        metadata_source: path.to_path_buf(),
        header: new_header,
    }))
}

/// Record a file's salt + `file_id` so a later re-encrypt reproduces byte-identical
/// ciphertext.
///
/// Only ever called after a fully successful decrypt: entries written before
/// the AEAD check would cache files that never decrypted (wrong password /
/// corrupted data) and could be reused incorrectly.
pub(super) fn record_salt_cache(cache: Option<CacheRef<'_>>, header: &FileHeader) {
    if let Some(cache) = cache {
        cache.sender.insert(
            cache.key,
            CachedEntry {
                salt: header.salt,
                file_id: header.file_id,
            },
        );
    }
}
