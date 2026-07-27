use std::{
    fs,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

use chacha20poly1305::{XChaCha20Poly1305, aead::KeyInit};
use log::{debug, warn};
use tempfile::NamedTempFile;

use crate::{
    crypt::{
        header::{FILE_ID_LEN, FileHeader, HEADER_LEN, MAGIC, SALT_LEN, is_encrypted_version},
        key::{KeyCache, get_or_derive_key, split_keys},
        stream::{decrypt_body, encrypt_into},
    },
    error::{Error, Result},
    salt_cache::{CacheRef, CachedEntry},
};

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

/// Encrypt `src` into `dst`.
///
/// `derived_key` is the **Argon2 output** (`&[u8; 32]`), NOT the raw password.
/// See "Key Semantics" in the [module docs](crate::crypt).
pub fn encrypt_file_to(
    src: &Path,
    dst: &Path,
    derived_key: &[u8; 32],
    salt: [u8; SALT_LEN],
    file_id: Option<[u8; FILE_ID_LEN]>,
    zstd: Option<u8>,
) -> Result<Option<FileHeader>> {
    let mut src_file = fs::File::open(src)?;

    let mut header_bytes = [0u8; HEADER_LEN];
    if src_file.read_exact(&mut header_bytes).is_ok()
        && &header_bytes[0..5] == MAGIC
        && is_encrypted_version(header_bytes[5])
    {
        warn!("Source file already encrypted, skipping: {}", src.display());
        return Ok(None);
    }
    src_file.seek(SeekFrom::Start(0))?;

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

    drop(src_file);
    persist_temp_file(temp_file, dst, Some(src))?;

    Ok(Some(header))
}

/// Decrypt `src` into `dst`.
///
/// `master_key` is the **raw password** (Argon2 is applied internally using
/// the header salt), NOT a derived key. See "Key Semantics" in the
/// [module docs](crate::crypt).
pub fn decrypt_file_to(src: &Path, dst: &Path, master_key: &[u8]) -> Result<Option<FileHeader>> {
    let mut src_file = fs::File::open(src)?;

    let mut header_bytes = [0u8; HEADER_LEN];
    if src_file.read_exact(&mut header_bytes).is_err() {
        debug!(
            "File too small to be encrypted, skipping: {}",
            src.display()
        );
        return Ok(None);
    }
    if &header_bytes[0..5] != MAGIC || !is_encrypted_version(header_bytes[5]) {
        debug!("File not encrypted (no magic), skipping: {}", src.display());
        return Ok(None);
    }

    debug!("Decrypting {} → {}", src.display(), dst.display());

    let header = *FileHeader::from_bytes(&header_bytes)?;
    let derived_key = super::key::derive_key(master_key, &header.salt)?;

    let dst_parent = dst.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dst_parent)?;
    let mut temp_file = NamedTempFile::new_in(dst_parent)?;

    let (key_enc, _) = split_keys(&derived_key);
    let cipher = XChaCha20Poly1305::new(key_enc.as_ref().into());
    decrypt_body(&mut src_file, &mut temp_file, &cipher, &header)?;

    drop(src_file);
    persist_temp_file(temp_file, dst, Some(src))?;

    Ok(Some(header))
}

/// Encrypt a single file **in place**.
///
/// `derived_key` is the **Argon2 output** (`&[u8; 32]`), NOT the raw password.
pub fn encrypt_file(
    path: &Path,
    derived_key: &[u8; 32],
    salt: &[u8; SALT_LEN],
    file_id: Option<[u8; FILE_ID_LEN]>,
    zstd: Option<u8>,
) -> Result<Option<FileHeader>> {
    encrypt_file_to(path, path, derived_key, *salt, file_id, zstd)
}

/// Decrypt a single file **in place**.
///
/// `master_key` is the **raw password**, NOT a derived key.
pub fn decrypt_file(path: &Path, master_key: &[u8]) -> Result<()> {
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
    master_key: &[u8],
) -> Result<()> {
    let mut file = fs::File::open(path)?;

    let mut header_bytes = [0u8; HEADER_LEN];
    if file.read_exact(&mut header_bytes).is_err() {
        debug!(
            "File too small to be encrypted, skipping: {}",
            path.display()
        );
        return Ok(());
    }
    if &header_bytes[0..5] != MAGIC || !is_encrypted_version(header_bytes[5]) {
        debug!(
            "File not encrypted (no magic), skipping: {}",
            path.display()
        );
        return Ok(());
    }

    debug!("Decrypting: {}", path.display());
    let header = *FileHeader::from_bytes(&header_bytes)?;

    let derived_key = get_or_derive_key(key_cache, master_key, &header.salt)?;

    let (key_enc, _key_mac) = split_keys(&derived_key);
    let cipher = XChaCha20Poly1305::new(key_enc.as_ref().into());
    let parent_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp_file = NamedTempFile::new_in(parent_dir)?;

    decrypt_body(&mut file, &mut temp_file, &cipher, &header)?;
    drop(file);

    persist_temp_file(temp_file, path, Some(path))?;

    // Record salt + file_id only after a fully successful decrypt: entries
    // written before the AEAD check would cache files that never decrypted
    // (wrong password / corrupted data) and could be reused incorrectly.
    if let Some(cache) = cache {
        cache.sender.insert(
            cache.key,
            CachedEntry {
                salt: header.salt,
                file_id: header.file_id,
            },
        );
    }

    Ok(())
}
