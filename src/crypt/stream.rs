use std::io::{Read, Write};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use zeroize::Zeroizing;

use crate::{
    crypt::{
        header::{
            AAD_LEN, CHUNK_SIZE, FILE_ID_LEN, FILE_ID_OFFSET, FileHeader, HEADER_LEN, NONCE_LEN,
            TAG_LEN,
        },
        key::{DerivedKey, Password, derive_key, derive_nonce, split_keys},
    },
    error::{Error, Result},
};

/// Build the file cipher from a 32-byte encryption key.
pub(super) fn new_cipher(key_enc: &[u8; 32]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new_from_slice(key_enc).expect("key is 32 bytes")
}

/// Streaming encryption loop: read plaintext chunks from `reader`, encrypt
/// each with the cipher, and write `[NONCE | CIPHERTEXT | TAG]` to `writer`.
fn encrypt_chunks(
    reader: &mut dyn Read,
    writer: &mut dyn std::io::Write,
    cipher: &XChaCha20Poly1305,
    key_mac: &[u8; 32],
    file_id: &[u8; FILE_ID_LEN],
    header_bytes: &[u8; HEADER_LEN],
) -> Result<()> {
    let mut buffer = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
    let mut out_buf: Vec<u8> = Vec::with_capacity(NONCE_LEN + CHUNK_SIZE + 16);
    let mut aad = [0u8; AAD_LEN];
    aad[..HEADER_LEN].copy_from_slice(header_bytes);
    // The AAD chain (v4) binds every chunk to its predecessor's Poly1305
    // tag. A ciphertext block replayed from an older version of the same
    // file then breaks authentication at the following chunk, so any splice
    // collapses to a full-file revert (H-04). The chain is seeded with the
    // (already AAD-bound) file_id.
    let mut chain = *file_id;
    let mut chunk_idx = 0u64;

    loop {
        let mut bytes_read = 0;
        while bytes_read < CHUNK_SIZE {
            let n = reader.read(&mut buffer[bytes_read..])?;
            if n == 0 {
                break;
            }
            bytes_read += n;
        }

        let is_last_chunk = bytes_read < CHUNK_SIZE;
        aad[HEADER_LEN..HEADER_LEN + TAG_LEN].copy_from_slice(&chain);
        aad[HEADER_LEN + TAG_LEN..HEADER_LEN + TAG_LEN + 8]
            .copy_from_slice(&chunk_idx.to_le_bytes());
        aad[HEADER_LEN + TAG_LEN + 8] = u8::from(is_last_chunk);

        // The nonce is derived only AFTER the AAD is fully assembled: it
        // must cover the entire AEAD input (see `derive_nonce`).
        let nonce_bytes = derive_nonce(key_mac, &aad, &buffer[..bytes_read]);
        let nonce = XNonce::from(nonce_bytes);

        let payload = Payload {
            msg: &buffer[..bytes_read],
            aad: &aad,
        };

        let ciphertext = cipher
            .encrypt(&nonce, payload)
            .map_err(|e| Error::EncryptFailed(e.to_string()))?;
        chain.copy_from_slice(&ciphertext[ciphertext.len() - TAG_LEN..]);

        out_buf.clear();
        out_buf.extend_from_slice(&nonce_bytes);
        out_buf.extend_from_slice(&ciphertext);
        writer.write_all(&out_buf)?;

        chunk_idx += 1;

        if is_last_chunk {
            break;
        }
    }

    Ok(())
}

/// Streaming decryption loop: read encrypted chunks from `reader`, decrypt,
/// and write plaintext to `writer`.
///
/// Chunk layout: `[NONCE (24B)] [CIPHERTEXT] [TAG (16B)]`
fn decrypt_chunks(
    reader: &mut dyn Read,
    writer: &mut dyn std::io::Write,
    cipher: &XChaCha20Poly1305,
    header_bytes: &[u8; HEADER_LEN],
) -> Result<()> {
    let mut nonce_buf = [0u8; NONCE_LEN];
    let mut ct_buffer = Zeroizing::new(vec![0u8; CHUNK_SIZE + TAG_LEN]);
    let ct_len = ct_buffer.len();
    let mut aad = [0u8; AAD_LEN];
    aad[..HEADER_LEN].copy_from_slice(header_bytes);
    // Chain seed: the file_id from the header (see encrypt side).
    let mut chain = [0u8; TAG_LEN];
    chain.copy_from_slice(&header_bytes[FILE_ID_OFFSET..FILE_ID_OFFSET + TAG_LEN]);
    let mut last_chunk_was_final = false;
    let mut chunk_idx = 0u64;

    loop {
        match reader.read_exact(&mut nonce_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }

        let mut bytes_read = 0;
        while bytes_read < ct_len {
            let n = reader.read(&mut ct_buffer[bytes_read..])?;
            if n == 0 {
                break;
            }
            bytes_read += n;
        }

        if bytes_read == 0 {
            return Err(Error::TruncatedChunk);
        }

        let is_last_chunk = bytes_read < ct_len;

        aad[HEADER_LEN..HEADER_LEN + TAG_LEN].copy_from_slice(&chain);
        aad[HEADER_LEN + TAG_LEN..HEADER_LEN + TAG_LEN + 8]
            .copy_from_slice(&chunk_idx.to_le_bytes());
        aad[HEADER_LEN + TAG_LEN + 8] = u8::from(is_last_chunk);

        let nonce = XNonce::from(nonce_buf);
        let payload = chacha20poly1305::aead::Payload {
            msg: &ct_buffer[..bytes_read],
            aad: &aad,
        };

        let plaintext = Zeroizing::new(
            cipher
                .decrypt(&nonce, payload)
                .map_err(|e| Error::DecryptFailed(e.to_string()))?,
        );

        // The tag read from the file becomes the next chunk's chain link —
        // it only matches the encryption-time chain if every preceding
        // chunk is authentic and in order.
        chain.copy_from_slice(&ct_buffer[bytes_read - TAG_LEN..bytes_read]);

        writer.write_all(&plaintext)?;

        chunk_idx += 1;

        if is_last_chunk {
            last_chunk_was_final = true;
            break;
        }
    }

    if !last_chunk_was_final {
        return Err(Error::FileTruncated);
    }

    Ok(())
}

/// Try to decrypt only the first chunk of an encrypted blob with the given
/// password.
///
/// `blob` must start at the file header and contain at least the first
/// chunk (header + nonce + ciphertext + tag); extra trailing bytes are
/// ignored. Returns `Ok(true)` when the first chunk authenticates,
/// `Ok(false)` on AEAD failure (wrong password or tampered data), and `Err`
/// when the blob cannot be parsed as a v4 GITSE file. Used for password
/// pre-checks (see [`crate::crypt::verify_password_against_head`]).
pub(super) fn check_first_chunk(master_key: Password<'_>, blob: &[u8]) -> Result<bool> {
    let mut cursor = std::io::Cursor::new(blob);
    let header = FileHeader::read_from(&mut cursor)?;
    let derived_key = derive_key(master_key, &header.salt)?;
    check_first_chunk_with_key(&derived_key, blob, &header)
}

/// [`check_first_chunk`] with an already-derived key, so a batch of anchors
/// sharing a salt costs one Argon2 derivation instead of one per anchor
/// (see the password verification against `HEAD`, which must not cap how
/// many anchors it tries).
pub(super) fn check_first_chunk_with_key(
    derived_key: &DerivedKey,
    blob: &[u8],
    header: &FileHeader,
) -> Result<bool> {
    let (key_enc, _) = split_keys(derived_key);
    let cipher = new_cipher(&key_enc);

    let body = &blob[HEADER_LEN..];
    if body.len() < NONCE_LEN + TAG_LEN {
        return Err(Error::TruncatedChunk);
    }
    let (nonce_bytes, rest) = body.split_at(NONCE_LEN);
    // A well-formed encrypted file never ends exactly at a full-chunk
    // boundary (a final short — possibly empty — chunk always follows), so
    // `take == CHUNK_SIZE + TAG_LEN` unambiguously means "not the last chunk".
    let take = rest.len().min(CHUNK_SIZE + TAG_LEN);
    let is_last_chunk = take < CHUNK_SIZE + TAG_LEN;

    let mut aad = [0u8; AAD_LEN];
    aad[..HEADER_LEN].copy_from_slice(header.as_bytes());
    // Chain seed for chunk 0 is the file_id; chunk_idx = 0 → zero bytes.
    aad[HEADER_LEN..HEADER_LEN + TAG_LEN].copy_from_slice(&header.file_id);
    aad[HEADER_LEN + TAG_LEN + 8] = u8::from(is_last_chunk);

    let payload = Payload {
        msg: &rest[..take],
        aad: &aad,
    };
    let nonce: &XNonce = nonce_bytes.try_into().expect("nonce is 24 bytes");
    Ok(cipher.decrypt(nonce, payload).is_ok())
}

/// Decrypt the body (with optional Zstd decompression)
pub(super) fn decrypt_body(
    reader: &mut dyn Read,
    writer: &mut dyn std::io::Write,
    cipher: &XChaCha20Poly1305,
    header: &FileHeader,
) -> Result<()> {
    if header.is_compressed() {
        let mut decoder = zstd::stream::write::Decoder::new(writer)?.auto_flush();
        decrypt_chunks(reader, &mut decoder, cipher, header.as_bytes())?;
        decoder.flush()?;
    } else {
        decrypt_chunks(reader, writer, cipher, header.as_bytes())?;
    }
    Ok(())
}

/// Encrypt data from `reader` into `writer` using streaming chunked encryption.
///
/// `derived_key` is the **Argon2 output** (`&[u8; 32]`, see [`derive_key`]),
/// NOT the raw password. See "Key Semantics" in the [module docs](crate::crypt).
pub fn encrypt_into<R: Read, W: std::io::Write>(
    reader: &mut R,
    writer: &mut W,
    derived_key: &DerivedKey,
    salt: [u8; crate::crypt::header::SALT_LEN],
    file_id: Option<[u8; FILE_ID_LEN]>,
    zstd: Option<u8>,
) -> Result<FileHeader> {
    let file_id = file_id.unwrap_or_else(FileHeader::generate_file_id);
    let header = FileHeader::new(zstd.is_some(), salt, file_id);
    header.write_to(writer)?;

    let (key_enc, key_mac) = split_keys(derived_key);
    let cipher = new_cipher(&key_enc);

    if let Some(level) = zstd {
        let mut encoder = zstd::stream::read::Encoder::new(reader, i32::from(level))?;
        encrypt_chunks(
            &mut encoder,
            writer,
            &cipher,
            &key_mac,
            &file_id,
            header.as_bytes(),
        )?;
    } else {
        encrypt_chunks(
            reader,
            writer,
            &cipher,
            &key_mac,
            &file_id,
            header.as_bytes(),
        )?;
    }

    Ok(header)
}

/// Decrypt data from `reader` into `writer`.
///
/// `master_key` is the **raw password**; Argon2 derivation happens internally
/// using the salt stored in the stream's header. Do NOT pass an
/// already-derived key here. See "Key Semantics" in the
/// [module docs](crate::crypt).
pub fn decrypt_into<R: Read, W: std::io::Write>(
    reader: &mut R,
    writer: &mut W,
    master_key: Password<'_>,
) -> Result<FileHeader> {
    let header = FileHeader::read_from(reader)?;

    let derived_key = derive_key(master_key, &header.salt)?;
    let (key_enc, _) = split_keys(&derived_key);
    let cipher = new_cipher(&key_enc);

    decrypt_body(reader, writer, &cipher, &header)?;
    Ok(header)
}
