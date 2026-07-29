use std::{
    io::{Read, Seek, Write},
    path::{Path, PathBuf},
};

use dashmap::DashMap;
use rand::Rng;
use tempfile::{NamedTempFile, TempDir, TempPath};

use crate::salt_cache::{CacheRef, SaltCacheReader, create_writer};

use super::{
    batch::*,
    file::*,
    header::*,
    key::*,
    stream::{decrypt_into, encrypt_into},
};

// --- Helper Functions ---

fn get_test_key_and_salt() -> (DerivedKey, [u8; SALT_LEN]) {
    let password = b"super_secret_password";
    let mut salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut salt);
    let key = derive_key(Password::new(password), &salt).unwrap();
    (key, salt)
}

fn create_temp_file(content: &[u8]) -> TempPath {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(content).unwrap();
    file.flush().unwrap();
    file.into_temp_path()
}

// --- Tests ---

/// Regression (2026-07 audit): the public library API must reject an empty
/// password at the shared derivation funnel, not only in the CLI layer —
/// `derive_key(Password::new(b""), ...)` used to succeed.
#[test]
fn test_derive_key_rejects_empty_password() {
    let result = derive_key(Password::new(b""), &[0x42; SALT_LEN]);
    assert!(
        matches!(result, Err(crate::error::Error::EmptyKey)),
        "an empty password must be rejected, got {result:?}"
    );
}

#[test]
fn test_header_serialization() {
    let salt = [0xAB; SALT_LEN];
    let file_id = FileHeader::generate_file_id();
    let header = FileHeader::new(true, salt, file_id);

    let mut buf = Vec::new();
    header.write_to(&mut buf).unwrap();
    assert_eq!(buf.len(), HEADER_LEN);

    let raw: &[u8; HEADER_LEN] = buf.as_slice().try_into().unwrap();
    let decoded = FileHeader::from_bytes(raw).unwrap();

    assert_eq!(decoded.magic, *MAGIC);
    assert_eq!(decoded.version, VERSION);
    assert_eq!(decoded.flags, FLAG_COMPRESSED);
    assert_eq!(decoded.enc_algo, ENC_ALGO);
    assert_eq!(decoded.salt, salt);
    assert_eq!(decoded.file_id, header.file_id);
    assert_eq!(decoded.reserved, [0u8; RESERVED_LEN]);
    assert!(decoded.is_compressed());
}

/// Build a v4 AAD exactly as the encrypt loop does:
/// `HEADER || chain (prev tag / file_id seed) || chunk_idx (8B LE) || is_last`.
fn test_aad(
    header: &FileHeader,
    chain: &[u8; TAG_LEN],
    chunk_idx: u64,
    is_last: bool,
) -> [u8; AAD_LEN] {
    let mut aad = [0u8; AAD_LEN];
    aad[..HEADER_LEN].copy_from_slice(header.as_bytes());
    aad[HEADER_LEN..HEADER_LEN + TAG_LEN].copy_from_slice(chain);
    aad[HEADER_LEN + TAG_LEN..HEADER_LEN + TAG_LEN + 8].copy_from_slice(&chunk_idx.to_le_bytes());
    aad[HEADER_LEN + TAG_LEN + 8] = u8::from(is_last);
    aad
}

#[test]
fn test_nonce_derivation_deterministic() {
    let key_mac = [0x42u8; 32];
    let header = FileHeader::new(false, [0x11; SALT_LEN], [0x99; FILE_ID_LEN]);
    let plaintext = b"hello world";

    let nonce0_a = derive_nonce(
        &key_mac,
        &test_aad(&header, &header.file_id, 0, true),
        plaintext,
    );
    let nonce0_b = derive_nonce(
        &key_mac,
        &test_aad(&header, &header.file_id, 0, true),
        plaintext,
    );
    assert_eq!(nonce0_a, nonce0_b);

    // A different chunk index (via the AAD) changes the nonce.
    let nonce1 = derive_nonce(
        &key_mac,
        &test_aad(&header, &header.file_id, 1, true),
        plaintext,
    );
    assert_ne!(nonce0_a, nonce1);

    // A different chain link (predecessor tag) changes the nonce — the core
    // of the 2026-07 audit fix: the AAD changed, so the nonce MUST change.
    let chain2 = [0x77; TAG_LEN];
    let nonce_chain2 = derive_nonce(&key_mac, &test_aad(&header, &chain2, 0, true), plaintext);
    assert_ne!(nonce0_a, nonce_chain2);

    let other_plaintext = b"hello world!";
    let nonce_other = derive_nonce(
        &key_mac,
        &test_aad(&header, &header.file_id, 0, true),
        other_plaintext,
    );
    assert_ne!(nonce0_a, nonce_other);

    let key_mac2 = [0x43u8; 32];
    let nonce_key2 = derive_nonce(
        &key_mac2,
        &test_aad(&header, &header.file_id, 0, true),
        plaintext,
    );
    assert_ne!(nonce0_a, nonce_key2);

    let header2 = FileHeader::new(false, [0x11; SALT_LEN], [0xAA; FILE_ID_LEN]);
    let nonce_file2 = derive_nonce(
        &key_mac,
        &test_aad(&header2, &header2.file_id, 0, true),
        plaintext,
    );
    assert_ne!(nonce0_a, nonce_file2);

    let nonce_empty = derive_nonce(&key_mac, &test_aad(&header, &header.file_id, 0, true), b"");
    assert_ne!(nonce_empty, [0u8; NONCE_LEN]);
}

/// Regression (2026-07 audit, critical): an unchanged tail chunk of a
/// re-encrypted file must NEVER reuse the nonce it was previously encrypted
/// with. v4's AAD chain changed such a chunk's AAD (the predecessor's tag)
/// without changing its nonce, so one (key, nonce) pair authenticated two
/// different AADs — reusing the Poly1305 one-time key and voiding the chain's
/// anti-splice guarantee. The nonce now covers the full AAD, so any prefix
/// change re-randomizes every later chunk.
#[test]
fn test_nonce_recovers_when_prefix_changes() {
    const REC: usize = NONCE_LEN + CHUNK_SIZE + 16;

    fn chunk_nonce(c: &[u8], i: usize) -> &[u8] {
        &c[HEADER_LEN + i * REC..HEADER_LEN + i * REC + NONCE_LEN]
    }

    let password = b"test_password";
    let salt = [0x42; SALT_LEN];
    let file_id = [0x13; FILE_ID_LEN];
    let key = derive_key(Password::new(password), &salt).unwrap();

    // v1 and v2 share their second chunk; only chunk 0 differs.
    let tail = vec![0xAB; CHUNK_SIZE];
    let v1 = [vec![0x11; CHUNK_SIZE], tail.clone()].concat();
    let v2 = [vec![0x22; CHUNK_SIZE], tail].concat();

    let mut c1 = Vec::new();
    encrypt_into(&mut &v1[..], &mut c1, &key, salt, Some(file_id), None).unwrap();
    let mut c2 = Vec::new();
    encrypt_into(&mut &v2[..], &mut c2, &key, salt, Some(file_id), None).unwrap();
    assert_eq!(c1.len(), c2.len());

    assert_ne!(
        chunk_nonce(&c1, 1),
        chunk_nonce(&c2, 1),
        "an unchanged tail chunk must get a FRESH nonce once the prefix changed"
    );
    assert_ne!(
        &c1[HEADER_LEN + REC..],
        &c2[HEADER_LEN + REC..],
        "the tail chunk's stored bytes (nonce|ciphertext|tag) must differ entirely"
    );

    // Both versions still decrypt to their plaintexts (old and new files
    // alike: the nonce is read from the file, never re-derived).
    let mut d1 = Vec::new();
    decrypt_into(&mut &c1[..], &mut d1, Password::new(password)).unwrap();
    let mut d2 = Vec::new();
    decrypt_into(&mut &c2[..], &mut d2, Password::new(password)).unwrap();
    assert_eq!(d1, v1);
    assert_eq!(d2, v2);
}

/// The deterministic guarantee is unaffected by the nonce fix: identical
/// plaintext under the same salt + `file_id` still re-encrypts byte-identical
/// (every chunk, not just the file as a whole).
#[test]
fn test_nonce_fix_preserves_determinism_multi_chunk() {
    let password = b"test_password";
    let salt = [0x42; SALT_LEN];
    let file_id = [0x13; FILE_ID_LEN];
    let key = derive_key(Password::new(password), &salt).unwrap();

    let plaintext = [vec![0x11; CHUNK_SIZE], vec![0x22; 1234]].concat();
    let mut c1 = Vec::new();
    encrypt_into(
        &mut &plaintext[..],
        &mut c1,
        &key,
        salt,
        Some(file_id),
        None,
    )
    .unwrap();
    let mut c2 = Vec::new();
    encrypt_into(
        &mut &plaintext[..],
        &mut c2,
        &key,
        salt,
        Some(file_id),
        None,
    )
    .unwrap();
    assert_eq!(c1, c2, "identical input must re-encrypt byte-identical");
}

#[test]
fn test_encrypt_decrypt_basic_no_compression() {
    let plaintext = b"Hello, World! This is a test without compression.";
    let path = create_temp_file(plaintext);

    let (key, salt) = get_test_key_and_salt();
    let master_key = b"super_secret_password";

    encrypt_file(&path, &key, &salt, None, None).unwrap();

    let mut encrypted_content = Vec::new();
    std::fs::File::open(&path)
        .unwrap()
        .read_to_end(&mut encrypted_content)
        .unwrap();
    assert_ne!(encrypted_content, plaintext);
    assert_eq!(&encrypted_content[0..5], MAGIC);
    assert_eq!(encrypted_content[5], VERSION);

    decrypt_file(&path, Password::new(master_key)).unwrap();

    let mut decrypted_content = Vec::new();
    std::fs::File::open(path)
        .unwrap()
        .read_to_end(&mut decrypted_content)
        .unwrap();
    assert_eq!(decrypted_content, plaintext);
}

#[test]
fn test_encrypt_decrypt_with_compression() {
    let plaintext = b"A".repeat(10000);
    let path = create_temp_file(&plaintext);

    let (key, salt) = get_test_key_and_salt();
    let master_key = b"super_secret_password";

    encrypt_file(&path, &key, &salt, None, Some(3)).unwrap();

    let encrypted_meta = std::fs::metadata(&path).unwrap();
    assert!(encrypted_meta.len() < 5000);

    decrypt_file(&path, Password::new(master_key)).unwrap();

    let mut decrypted_content = Vec::new();
    std::fs::File::open(path)
        .unwrap()
        .read_to_end(&mut decrypted_content)
        .unwrap();
    assert_eq!(decrypted_content, plaintext);
}

#[test]
#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::cast_sign_loss)]
fn test_chunked_encryption_large_file() {
    let plaintext = {
        let mut data = Vec::with_capacity(100_000);
        for i in 0..100_000 {
            data.push((i % 256) as u8);
        }
        data
    };

    let path = create_temp_file(&plaintext);

    let (key, salt) = get_test_key_and_salt();
    let master_key = b"super_secret_password";

    encrypt_file(&path, &key, &salt, None, None).unwrap();
    decrypt_file(&path, Password::new(master_key)).unwrap();

    let mut decrypted_content = Vec::new();
    std::fs::File::open(path)
        .unwrap()
        .read_to_end(&mut decrypted_content)
        .unwrap();
    assert_eq!(decrypted_content, plaintext);
}

#[test]
fn test_tamper_resistance() {
    let plaintext = b"Sensitive data that should not be tampered with.";
    let path = create_temp_file(plaintext);

    let (key, salt) = get_test_key_and_salt();
    let master_key = b"super_secret_password";

    encrypt_file(&path, &key, &salt, None, None).unwrap();

    let mut encrypted_content = Vec::new();
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    f.read_to_end(&mut encrypted_content).unwrap();

    encrypted_content[HEADER_LEN + 5] ^= 0xFF;

    f.seek(std::io::SeekFrom::Start(0)).unwrap();
    f.write_all(&encrypted_content).unwrap();
    drop(f);

    let result = decrypt_file(&path, Password::new(master_key));

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .to_lowercase()
            .contains("decryption failed")
    );
}

#[test]
fn test_header_tamper_detected() {
    let plaintext = b"Test data with header integrity check.";
    let path = create_temp_file(plaintext);

    let (key, salt) = get_test_key_and_salt();
    let master_key = b"super_secret_password";

    encrypt_file(&path, &key, &salt, None, None).unwrap();

    let mut encrypted_content = Vec::new();
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    f.read_to_end(&mut encrypted_content).unwrap();

    encrypted_content[6] ^= FLAG_COMPRESSED;

    f.seek(std::io::SeekFrom::Start(0)).unwrap();
    f.write_all(&encrypted_content).unwrap();
    drop(f);

    let result = decrypt_file(&path, Password::new(master_key));
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .to_lowercase()
            .contains("decryption failed")
    );
}

#[test]
fn test_deterministic_encrypt_with_fixed_salt_file_id() {
    let plaintext = b"Deterministic encryption test data.";

    let password = b"test_password";
    let salt = [0x42; SALT_LEN];
    let file_id = [0x13; FILE_ID_LEN];
    let key = derive_key(Password::new(password), &salt).unwrap();

    let path1 = create_temp_file(plaintext);
    let path2 = create_temp_file(plaintext);

    encrypt_file(&path1, &key, &salt, Some(file_id), None).unwrap();
    encrypt_file(&path2, &key, &salt, Some(file_id), None).unwrap();

    let ct1 = std::fs::read(&path1).unwrap();
    let ct2 = std::fs::read(&path2).unwrap();
    assert_eq!(
        ct1, ct2,
        "Same plaintext + same salt+file_id must produce identical ciphertext"
    );

    decrypt_file(&path1, Password::new(password)).unwrap();
    assert_eq!(std::fs::read(&path1).unwrap(), plaintext);
}

#[test]
fn test_deterministic_encrypt_multi_chunk() {
    #[allow(clippy::cast_possible_truncation)]
    let plaintext = {
        let mut data = Vec::with_capacity(CHUNK_SIZE * 2 + 1000);
        for i in 0..(CHUNK_SIZE * 2 + 1000) {
            data.push(i as u8);
        }
        data
    };

    let password = b"test_password";
    let salt = [0x42; SALT_LEN];
    let file_id = [0x13; FILE_ID_LEN];
    let key = derive_key(Password::new(password), &salt).unwrap();

    let path1 = create_temp_file(&plaintext);
    let path2 = create_temp_file(&plaintext);

    encrypt_file(&path1, &key, &salt, Some(file_id), None).unwrap();
    encrypt_file(&path2, &key, &salt, Some(file_id), None).unwrap();

    let ct1 = std::fs::read(&path1).unwrap();
    let ct2 = std::fs::read(&path2).unwrap();
    assert_eq!(
        ct1, ct2,
        "Same multi-chunk plaintext + same salt+file_id must produce identical ciphertext"
    );

    decrypt_file(&path1, Password::new(password)).unwrap();
    assert_eq!(std::fs::read(&path1).unwrap(), plaintext);
}

#[test]
fn test_different_file_id_produces_different_ciphertext() {
    let plaintext = b"Same content, different file.";

    let password = b"test_password";
    let salt = [0x42; SALT_LEN];
    let key = derive_key(Password::new(password), &salt).unwrap();

    let path1 = create_temp_file(plaintext);
    let path2 = create_temp_file(plaintext);

    let file_id1 = [0x01; FILE_ID_LEN];
    let file_id2 = [0x02; FILE_ID_LEN];

    encrypt_file(&path1, &key, &salt, Some(file_id1), None).unwrap();
    encrypt_file(&path2, &key, &salt, Some(file_id2), None).unwrap();

    let ct1 = std::fs::read(&path1).unwrap();
    let ct2 = std::fs::read(&path2).unwrap();
    assert_ne!(
        ct1, ct2,
        "Same plaintext with different File_IDs must produce different ciphertext"
    );

    decrypt_file(&path1, Password::new(password)).unwrap();
    assert_eq!(std::fs::read(&path1).unwrap(), plaintext);
    decrypt_file(&path2, Password::new(password)).unwrap();
    assert_eq!(std::fs::read(&path2).unwrap(), plaintext);
}

#[cfg(unix)]
#[test]
fn test_metadata_preservation() {
    use std::os::unix::fs::PermissionsExt;

    let plaintext = b"Executable script content";
    let file = create_temp_file(plaintext);
    let path: &Path = &file;

    let mut perms = std::fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).unwrap();

    let (key, salt) = get_test_key_and_salt();
    let master_key = b"super_secret_password";

    encrypt_file(path, &key, &salt, None, None).unwrap();

    let encrypted_perms = std::fs::metadata(path).unwrap().permissions();
    assert_eq!(encrypted_perms.mode() & 0o777, 0o755);

    let key_cache: KeyCache = DashMap::new();
    decrypt_file_with_cache(path, &key_cache, None, Password::new(master_key)).unwrap();

    let decrypted_perms = std::fs::metadata(path).unwrap().permissions();
    assert_eq!(decrypted_perms.mode() & 0o777, 0o755);
}

#[test]
fn test_empty_file_roundtrip() {
    let plaintext = b"";
    let path = create_temp_file(plaintext);

    let (key, salt) = get_test_key_and_salt();
    let master_key = b"super_secret_password";

    encrypt_file(&path, &key, &salt, None, None).unwrap();

    let enc = std::fs::read(&path).unwrap();
    assert_eq!(enc.len(), HEADER_LEN + NONCE_LEN + 16);

    decrypt_file(&path, Password::new(master_key)).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), plaintext);
}

#[test]
fn test_wrong_password_decrypt_fails() {
    let plaintext = b"data encrypted under one password";
    let path = create_temp_file(plaintext);

    let (key, salt) = get_test_key_and_salt();
    encrypt_file(&path, &key, &salt, None, None).unwrap();

    let result = decrypt_file(&path, Password::new(b"a_completely_different_password"));
    assert!(matches!(result, Err(crate::error::Error::DecryptFailed(_))));

    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(&bytes[..MAGIC.len()], MAGIC);
}

#[test]
fn test_truncated_ciphertext_after_nonce() {
    let plaintext = b"abc";
    let path = create_temp_file(plaintext);
    let (key, salt) = get_test_key_and_salt();
    encrypt_file(&path, &key, &salt, None, None).unwrap();

    let trunc_len = HEADER_LEN + NONCE_LEN;
    let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    f.set_len(trunc_len as u64).unwrap();
    drop(f);

    // The strict format probe catches this before any Argon2 work: a header
    // with no complete chunk behind it cannot be a valid encrypted file.
    let result = decrypt_file(&path, Password::new(b"super_secret_password"));
    assert!(matches!(result, Err(crate::error::Error::FileTruncated)));
}

#[test]
fn test_truncated_before_first_nonce() {
    let path = create_temp_file(b"tiny");
    let key_cache: KeyCache = DashMap::new();
    let res = decrypt_file_with_cache(&path, &key_cache, None, Password::new(b"any"));
    assert!(res.is_ok());
    assert_eq!(std::fs::read(&path).unwrap(), b"tiny");
}

// --- Streaming Core Tests (encrypt_into / decrypt_into) ---

#[test]
fn test_stream_encrypt_decrypt_roundtrip() {
    let plaintext = b"streaming core roundtrip test data";
    let (key, salt) = get_test_key_and_salt();
    let master_key = b"super_secret_password";

    let mut reader = std::io::Cursor::new(plaintext.to_vec());
    let mut ciphertext = Vec::new();
    let header = encrypt_into(&mut reader, &mut ciphertext, &key, salt, None, None).unwrap();

    assert_eq!(&ciphertext[0..5], MAGIC);
    assert_eq!(ciphertext[5], VERSION);

    let mut enc_reader = std::io::Cursor::new(ciphertext.clone());
    let mut decrypted = Vec::new();
    let dec_header =
        decrypt_into(&mut enc_reader, &mut decrypted, Password::new(master_key)).unwrap();

    assert_eq!(decrypted, plaintext);
    assert_eq!(header.salt, dec_header.salt);
    assert_eq!(header.file_id, dec_header.file_id);
}

#[test]
fn test_stream_encrypt_with_compression() {
    let plaintext = b"X".repeat(50_000);
    let (key, salt) = get_test_key_and_salt();
    let master_key = b"super_secret_password";

    let mut reader = std::io::Cursor::new(plaintext.clone());
    let mut ciphertext = Vec::new();
    encrypt_into(&mut reader, &mut ciphertext, &key, salt, None, Some(3)).unwrap();

    assert!(ciphertext.len() < 5_000);

    let mut enc_reader = std::io::Cursor::new(ciphertext);
    let mut decrypted = Vec::new();
    decrypt_into(&mut enc_reader, &mut decrypted, Password::new(master_key)).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_stream_encrypt_deterministic_with_fixed_file_id() {
    let plaintext = b"deterministic stream test";
    let (key, salt) = get_test_key_and_salt();
    let file_id = [0x42; FILE_ID_LEN];

    let mut r1 = std::io::Cursor::new(plaintext.to_vec());
    let mut c1 = Vec::new();
    encrypt_into(&mut r1, &mut c1, &key, salt, Some(file_id), None).unwrap();

    let mut r2 = std::io::Cursor::new(plaintext.to_vec());
    let mut c2 = Vec::new();
    encrypt_into(&mut r2, &mut c2, &key, salt, Some(file_id), None).unwrap();

    assert_eq!(c1, c2, "Same plaintext + salt + file_id must be identical");
}

// --- File-to-File Tests (encrypt_file_to / decrypt_file_to) ---

#[test]
fn test_encrypt_file_to_different_destination() {
    let plaintext = b"file-to-file test data";
    let src = create_temp_file(plaintext);
    let dst_dir = tempfile::TempDir::new().unwrap();
    let dst = dst_dir.path().join("output.enc");

    let (key, salt) = get_test_key_and_salt();
    let master_key = b"super_secret_password";

    let header = encrypt_file_to(&src, &dst, &key, salt, None, None).unwrap();
    assert!(header.is_some());

    assert_eq!(std::fs::read(&src).unwrap(), plaintext);

    let enc = std::fs::read(&dst).unwrap();
    assert_eq!(&enc[0..5], MAGIC);

    let dst2 = dst_dir.path().join("output.dec");
    let result = decrypt_file_to(&dst, &dst2, Password::new(master_key)).unwrap();
    assert!(result.is_some());

    assert_eq!(std::fs::read(&dst2).unwrap(), plaintext);
}

#[test]
fn test_encrypt_file_to_creates_parent_dirs() {
    let plaintext = b"nested dir test";
    let src = create_temp_file(plaintext);
    let dst_dir = tempfile::TempDir::new().unwrap();
    let dst = dst_dir.path().join("a/b/c/output.enc");

    let (key, salt) = get_test_key_and_salt();
    encrypt_file_to(&src, &dst, &key, salt, None, None).unwrap();

    assert!(dst.exists());
    assert_eq!(&std::fs::read(&dst).unwrap()[0..5], MAGIC);
}

#[test]
fn test_decrypt_file_to_skips_non_encrypted() {
    let src = create_temp_file(b"just plaintext, no encryption");
    let dst_dir = tempfile::TempDir::new().unwrap();
    let dst = dst_dir.path().join("out.txt");

    let result = decrypt_file_to(&src, &dst, Password::new(b"any_key")).unwrap();
    assert!(result.is_none(), "Should skip non-encrypted file");
    assert!(!dst.exists(), "Destination should not be created");
}

#[test]
fn test_encrypt_file_to_skips_already_encrypted() {
    let plaintext = b"already encrypted source";
    let (key, salt) = get_test_key_and_salt();

    let src = create_temp_file(plaintext);
    encrypt_file(&src, &key, &salt, None, None).unwrap();
    assert_eq!(&std::fs::read(&src).unwrap()[0..5], MAGIC);

    let dst_dir = tempfile::TempDir::new().unwrap();
    let dst = dst_dir.path().join("out2.enc");
    let result = encrypt_file_to(&src, &dst, &key, salt, None, None).unwrap();
    assert!(result.is_none(), "Should skip already-encrypted source");
    assert!(!dst.exists());
}

#[test]
fn test_encrypt_file_to_in_place_matches_encrypt_file() {
    let plaintext = b"in-place compatibility test";
    let (key, salt) = get_test_key_and_salt();

    let p1 = create_temp_file(plaintext);
    encrypt_file(&p1, &key, &salt, Some([0xAA; FILE_ID_LEN]), None).unwrap();

    let p2 = create_temp_file(plaintext);
    encrypt_file_to(&p2, &p2, &key, salt, Some([0xAA; FILE_ID_LEN]), None).unwrap();

    assert_eq!(std::fs::read(&p1).unwrap(), std::fs::read(&p2).unwrap());
}

// --- Batch API Tests ---

#[test]
fn test_decrypt_files_to_batch() {
    let master_key = b"batch_password";
    let (key, salt) = {
        let password = master_key;
        let mut s = [0u8; SALT_LEN];
        rand::rng().fill_bytes(&mut s);
        let k = derive_key(Password::new(password), &s).unwrap();
        (k, s)
    };

    let temp_paths: Vec<TempPath> = (0..3)
        .map(|i| {
            let path = create_temp_file(format!("batch item {i}").as_bytes());
            encrypt_file(&path, &key, &salt, None, None).unwrap();
            path
        })
        .collect();
    let sources: Vec<PathBuf> = temp_paths.iter().map(PathBuf::from).collect();

    let out_dir = tempfile::TempDir::new().unwrap();
    let summary = decrypt_files_to(&sources, Password::new(master_key), |src: &Path| {
        Some(out_dir.path().join(src.file_name().unwrap()))
    })
    .unwrap();

    assert_eq!(summary.total, 3);
    assert_eq!(summary.succeeded, 3);
    assert_eq!(summary.skipped, 0);
    assert_eq!(summary.failed, 0);
    assert!(summary.is_ok());

    for (i, src) in sources.iter().enumerate() {
        let dec_path = out_dir.path().join(src.file_name().unwrap());
        assert_eq!(
            std::fs::read(&dec_path).unwrap(),
            format!("batch item {i}").as_bytes()
        );
    }
}

#[test]
fn test_decrypt_files_to_skips_non_encrypted() {
    let temp_paths: Vec<TempPath> = (0..3)
        .map(|i| create_temp_file(format!("plaintext {i}").as_bytes()))
        .collect();
    let sources: Vec<PathBuf> = temp_paths.iter().map(PathBuf::from).collect();

    let out_dir = tempfile::TempDir::new().unwrap();
    let summary = decrypt_files_to(&sources, Password::new(b"any"), |src: &Path| {
        Some(out_dir.path().join(src.file_name().unwrap()))
    })
    .unwrap();

    assert_eq!(summary.total, 3);
    assert_eq!(summary.succeeded, 0);
    assert_eq!(summary.skipped, 3);
    assert_eq!(summary.failed, 0);
}

#[test]
fn test_decrypt_files_to_mapper_skip() {
    let master_key = b"batch_password";
    let mut salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut salt);
    let key = derive_key(Password::new(master_key), &salt).unwrap();

    let temp_paths: Vec<TempPath> = (0..3)
        .map(|i| {
            let path = create_temp_file(format!("item {i}").as_bytes());
            encrypt_file(&path, &key, &salt, None, None).unwrap();
            path
        })
        .collect();
    let sources: Vec<PathBuf> = temp_paths.iter().map(PathBuf::from).collect();

    let out_dir = tempfile::TempDir::new().unwrap();
    let skip_path = sources[1].clone();
    let summary = decrypt_files_to(&sources, Password::new(master_key), |src: &Path| {
        if src == skip_path.as_path() {
            None
        } else {
            Some(out_dir.path().join(src.file_name().unwrap()))
        }
    })
    .unwrap();

    assert_eq!(summary.succeeded, 2);
    assert!(summary.is_ok());
}

#[test]
fn test_encrypt_files_to_batch() {
    let master_key = b"batch_encrypt_password";

    let temp_paths: Vec<TempPath> = (0..3)
        .map(|i| create_temp_file(format!("source item {i}").as_bytes()))
        .collect();
    let sources: Vec<PathBuf> = temp_paths.iter().map(PathBuf::from).collect();

    let out_dir = tempfile::TempDir::new().unwrap();
    let summary = encrypt_files_to(
        &sources,
        Password::new(master_key),
        |src: &Path| Some(out_dir.path().join(src.file_name().unwrap())),
        None,
    )
    .unwrap();

    assert_eq!(summary.total, 3);
    assert_eq!(summary.succeeded, 3);
    assert_eq!(summary.failed, 0);
    assert!(summary.is_ok());

    for (i, src) in sources.iter().enumerate() {
        let enc_path = out_dir.path().join(src.file_name().unwrap());
        let enc = std::fs::read(&enc_path).unwrap();
        assert_eq!(&enc[0..5], MAGIC);

        let dec_path = out_dir.path().join(format!("dec_{i}"));
        decrypt_file_to(&enc_path, &dec_path, Password::new(master_key)).unwrap();
        assert_eq!(
            std::fs::read(&dec_path).unwrap(),
            format!("source item {i}").as_bytes()
        );
    }
}

/// Anti-replay (H-04, format v4): a ciphertext block replayed from an older
/// version of the same file (same salt + `file_id`, i.e. deterministic
/// re-encryption) must break the AAD chain and fail decryption.
#[test]
fn test_cross_version_chunk_replay_detected() {
    const REC: usize = NONCE_LEN + CHUNK_SIZE + 16;

    let password = b"test_password";
    let salt = [0x42; SALT_LEN];
    let file_id = [0x13; FILE_ID_LEN];
    let key = derive_key(Password::new(password), &salt).unwrap();

    // v1 = A + B, v2 = X + C (both 2 chunks, no compression for stable layout)
    let path = create_temp_file(&[vec![b'A'; CHUNK_SIZE], vec![b'B'; CHUNK_SIZE]].concat());
    encrypt_file(&path, &key, &salt, Some(file_id), None).unwrap();
    let v1_enc = std::fs::read(&path).unwrap();

    std::fs::write(
        &path,
        [vec![b'X'; CHUNK_SIZE], vec![b'C'; CHUNK_SIZE]].concat(),
    )
    .unwrap();
    encrypt_file(&path, &key, &salt, Some(file_id), None).unwrap();
    let v2_enc = std::fs::read(&path).unwrap();

    assert_eq!(&v1_enc[..HEADER_LEN], &v2_enc[..HEADER_LEN]);

    // Splice v1's chunk-0 record [nonce|ciphertext|tag] into v2.
    let mut spliced = v2_enc[..HEADER_LEN].to_vec();
    spliced.extend_from_slice(&v1_enc[HEADER_LEN..HEADER_LEN + REC]);
    spliced.extend_from_slice(&v2_enc[HEADER_LEN + REC..]);
    std::fs::write(&path, &spliced).unwrap();

    let result = decrypt_file(&path, Password::new(password));
    assert!(
        result.is_err(),
        "cross-version chunk replay must be detected by the AAD chain"
    );
}

/// A whole-file revert, however, is a legitimately valid ciphertext: it must
/// still decrypt (it IS the old file, not a forged mixture).
#[test]
fn test_full_file_revert_still_decrypts() {
    let password = b"test_password";
    let salt = [0x42; SALT_LEN];
    let file_id = [0x13; FILE_ID_LEN];
    let key = derive_key(Password::new(password), &salt).unwrap();

    let v1 = [vec![b'A'; CHUNK_SIZE], vec![b'B'; CHUNK_SIZE]].concat();
    let path = create_temp_file(&v1);
    encrypt_file(&path, &key, &salt, Some(file_id), None).unwrap();
    let v1_enc = std::fs::read(&path).unwrap();

    // Encrypt a different v2, then restore the complete v1 ciphertext.
    std::fs::write(&path, b"different content entirely").unwrap();
    encrypt_file(&path, &key, &salt, Some(file_id), None).unwrap();
    std::fs::write(&path, &v1_enc).unwrap();

    decrypt_file(&path, Password::new(password)).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), v1);
}

#[test]
fn test_failed_decrypt_does_not_poison_cache() {
    let plaintext = b"cache poisoning test data";
    let path = create_temp_file(plaintext);

    let (key, salt) = get_test_key_and_salt();
    encrypt_file(&path, &key, &salt, None, None).unwrap();

    // Corrupt the last byte (inside the final chunk's tag) so decryption fails.
    let mut data = std::fs::read(&path).unwrap();
    let last = data.len() - 1;
    data[last] ^= 0xFF;
    std::fs::write(&path, &data).unwrap();

    let dir = TempDir::new().unwrap();
    let git_dir = dir.path().join(".git");
    std::fs::create_dir_all(&git_dir).unwrap();
    let (sender, saver) = create_writer(&git_dir);

    let key_cache: KeyCache = DashMap::new();
    let res = decrypt_file_with_cache(
        &path,
        &key_cache,
        Some(CacheRef {
            sender: &sender,
            key: b"x.txt",
        }),
        Password::new(b"super_secret_password"),
    );
    assert!(res.is_err(), "decrypt of corrupted file must fail");

    drop(sender);
    saver.save().unwrap();

    let reader = SaltCacheReader::load(&git_dir).unwrap();
    assert_eq!(
        reader.get(b"x.txt"),
        None,
        "failed decrypt must not record a cache entry"
    );
}

/// Build a forged-but-well-formed v4 blob: valid header with the given salt
/// plus one complete garbage chunk. Passes the strict format probe; no key
/// stands behind it.
fn forged_blob(salt: [u8; SALT_LEN]) -> Vec<u8> {
    let header = FileHeader::new(false, salt, [0x88; FILE_ID_LEN]);
    let mut blob = header.as_bytes().to_vec();
    blob.extend_from_slice(&[0u8; NONCE_LEN + 16]);
    blob
}

/// Regression (2026-07 audit): the public batch encrypt must not silently
/// skip a ciphertext it cannot authenticate — a forged GITSE file, or one
/// encrypted under a different password, is an ERROR in the summary, while
/// a file encrypted under the SAME password is skipped cleanly.
#[test]
fn test_encrypt_files_to_authenticates_already_encrypted() {
    let dir = TempDir::new().unwrap();

    let forged = dir.path().join("forged.bin");
    std::fs::write(&forged, forged_blob([0x77; SALT_LEN])).unwrap();

    let foreign = create_temp_file(b"foreign");
    let foreign_key = derive_key(Password::new(b"other_password"), &[0x99; SALT_LEN]).unwrap();
    encrypt_file(&foreign, &foreign_key, &[0x99; SALT_LEN], None, None).unwrap();

    let ours = create_temp_file(b"ours");
    let ours_key = derive_key(Password::new(b"batch_pw"), &[0xAA; SALT_LEN]).unwrap();
    encrypt_file(&ours, &ours_key, &[0xAA; SALT_LEN], None, None).unwrap();

    let sources: Vec<PathBuf> = vec![forged, PathBuf::from(&foreign), PathBuf::from(&ours)];
    let out_dir = TempDir::new().unwrap();
    let summary = encrypt_files_to(
        &sources,
        Password::new(b"batch_pw"),
        |src: &Path| Some(out_dir.path().join(src.file_name().unwrap())),
        None,
    )
    .unwrap();

    assert_eq!(summary.total, 3);
    assert_eq!(summary.succeeded, 0);
    assert_eq!(summary.skipped, 1, "only the same-password file is skipped");
    assert_eq!(
        summary.failed, 2,
        "forged and foreign ciphertexts are errors"
    );
    assert!(!summary.is_ok());
    for (path, err) in &summary.errors {
        assert!(
            matches!(err, crate::error::Error::ForeignCiphertext(_)),
            "{} must be a foreign-ciphertext error, got {err:?}",
            path.display()
        );
    }

    // A same-password-only batch is a clean skip.
    let summary = encrypt_files_to(
        [ours.as_ref() as &Path],
        Password::new(b"batch_pw"),
        |src: &Path| Some(out_dir.path().join(src.file_name().unwrap())),
        None,
    )
    .unwrap();
    assert_eq!(summary.skipped, 1);
    assert!(summary.is_ok());
}

/// The batch APIs bound their Argon2 cost exactly like the repo operations:
/// more distinct salts among the sources than the (tiny, cfg(test)) budget
/// fails before any derivation runs.
#[test]
fn test_batch_apis_enforce_salt_budget() {
    let dir = TempDir::new().unwrap();
    let mut sources = Vec::new();
    for b in [0x11u8, 0x22, 0x33, 0x44] {
        let path = dir.path().join(format!("f{b:02x}.bin"));
        std::fs::write(&path, forged_blob([b; SALT_LEN])).unwrap();
        sources.push(path);
    }

    let err = decrypt_files_to(&sources, Password::new(b"pw"), |src| {
        Some(src.to_path_buf())
    })
    .unwrap_err();
    assert!(
        matches!(err, crate::error::Error::SaltBudgetExceeded(_)),
        "decrypt batch must hit the salt budget, got {err:?}"
    );
    let err = encrypt_files_to(
        &sources,
        Password::new(b"pw"),
        |src| Some(src.to_path_buf()),
        None,
    )
    .unwrap_err();
    assert!(
        matches!(err, crate::error::Error::SaltBudgetExceeded(_)),
        "encrypt batch must hit the salt budget, got {err:?}"
    );
}

#[test]
fn test_encrypt_files_to_with_compression() {
    let master_key = b"batch_compress_password";

    let temp_path = create_temp_file(&b"Z".repeat(30_000));
    let sources: Vec<PathBuf> = vec![temp_path.to_path_buf()];

    let out_dir = tempfile::TempDir::new().unwrap();
    let summary = encrypt_files_to(
        &sources,
        Password::new(master_key),
        |src: &Path| Some(out_dir.path().join(src.file_name().unwrap())),
        Some(15),
    )
    .unwrap();

    assert_eq!(summary.succeeded, 1);

    let enc_path = out_dir.path().join(sources[0].file_name().unwrap());
    assert!(std::fs::metadata(&enc_path).unwrap().len() < 5_000);
}

// --- Format-probe strictness (M-01) ---

/// Build a 64-byte header with arbitrary field values, bypassing the
/// constructor so invalid combinations can be produced.
fn raw_header(version: u8, flags: u8, algo: u8, reserved_byte: u8) -> Vec<u8> {
    let mut h = Vec::with_capacity(HEADER_LEN);
    h.extend_from_slice(MAGIC);
    h.extend_from_slice(&[version, flags, algo]);
    h.extend_from_slice(&[0x11; SALT_LEN]);
    h.extend_from_slice(&[0x22; FILE_ID_LEN]);
    h.extend_from_slice(&[reserved_byte; HEADER_LEN - 5 - 3 - SALT_LEN - FILE_ID_LEN]);
    assert_eq!(h.len(), HEADER_LEN);
    h
}

/// A valid header plus one complete (garbage) chunk — the minimum that
/// satisfies the *format* check. Not authentic ciphertext.
fn min_valid_blob() -> Vec<u8> {
    let mut b = raw_header(VERSION, 0, 1, 0);
    b.extend_from_slice(&[0u8; NONCE_LEN + 16]);
    b
}

#[test]
fn test_probe_header_rejects_crafted_headers() {
    // Plain files are plaintext, however short.
    assert_eq!(probe_header(b""), HeaderProbe::Plaintext);
    assert_eq!(probe_header(b"hello world"), HeaderProbe::Plaintext);
    // "GITS" is not the magic; "GITSE" alone is a truncated header.
    assert_eq!(probe_header(b"GITS"), HeaderProbe::Plaintext);
    assert_eq!(
        probe_header(b"GITSE"),
        HeaderProbe::Malformed(MalformedReason::TruncatedHeader)
    );

    let cases = [
        (raw_header(3, 0, 1, 0), MalformedReason::UnsupportedVersion),
        (
            raw_header(VERSION, 0, 99, 0),
            MalformedReason::UnsupportedAlgo,
        ),
        // Unknown flag bits: the crafted-header bypass from the audit.
        (
            raw_header(VERSION, 0x80, 1, 0),
            MalformedReason::UnknownFlags,
        ),
        (
            raw_header(VERSION, 0, 1, 0xAB),
            MalformedReason::ReservedNotZero,
        ),
        // A bare valid header with no chunk behind it.
        (
            raw_header(VERSION, 0, 1, 0),
            MalformedReason::NoCompleteChunk,
        ),
    ];
    for (bytes, expected) in cases {
        assert_eq!(
            probe_header(&bytes),
            HeaderProbe::Malformed(expected),
            "expected {expected:?}"
        );
    }

    assert_eq!(probe_header(&min_valid_blob()), HeaderProbe::Encrypted);
    assert!(is_encrypted_header(&min_valid_blob()));
}

/// Regression (M-01): a crafted header followed by real plaintext must never
/// be silently skipped by encrypt. It used to pass `check` too, which made it
/// a complete plaintext-commit channel.
#[test]
fn test_encrypt_refuses_crafted_header_with_plaintext() {
    let mut content = raw_header(VERSION, 0x80, 1, 0);
    content.extend_from_slice(b"TOP_SECRET_PLAINTEXT");
    let path = create_temp_file(&content);
    let (key, salt) = get_test_key_and_salt();

    let err = encrypt_file(&path, &key, &salt, None, None).unwrap_err();
    assert!(
        matches!(err, crate::error::Error::MalformedEncryptedFile(_, _)),
        "crafted header must be refused, not skipped: {err:?}"
    );
    // Refusing must not have modified the file.
    assert_eq!(std::fs::read(&path).unwrap(), content);
    assert!(!crate::utils::is_file_encrypted(&path).unwrap());
}

/// Regression (M-01): encrypt and check must agree. A file that encrypt
/// refuses to touch must not be reported as "already encrypted" by check,
/// and vice versa — the two used to disagree, leaving an unfixable state.
#[test]
fn test_encrypt_and_check_agree_on_every_probe_outcome() {
    let (key, salt) = get_test_key_and_salt();
    for bytes in [
        raw_header(VERSION, 0, 99, 0),   // bad algo
        raw_header(VERSION, 0x80, 1, 0), // unknown flags
        raw_header(VERSION, 0, 1, 0),    // header only
    ] {
        let path = create_temp_file(&bytes);
        let encrypt_skipped = matches!(encrypt_file(&path, &key, &salt, None, None), Ok(None));
        let check_says_encrypted = crate::utils::is_file_encrypted(&path).unwrap();
        assert_eq!(
            encrypt_skipped, check_says_encrypted,
            "encrypt-skips and check-passes must agree for {bytes:02x?}"
        );
    }
}
