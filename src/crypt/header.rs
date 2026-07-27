// GITSE Binary Header Layout (64 Bytes)
//  00          04  05  06  07           17                  27              3F
//  +-----------+---+---+---+-----------+-------------------+---------------+
//  |   MAGIC   | V | F | A |   SALT    |     `FILE_ID`     |   RESERVED    |
//  |  "GITSE"  |   |   |   | (16 bytes)|    (16 bytes)     |  (24 bytes)   |
//  +-----------+---+---+---+-----------+-------------------+---------------+
//    5 bytes     1   1   1    16 bytes       16 bytes          24 bytes
//                |   |   |
//     Version ---+   |   +--- Encryption Algo (1 = XChaCha20-Poly1305 Stream)
//                    |
//      Flags --------+ (Bit 0: Compression)

use rand::Rng;

pub const MAGIC: &[u8; 5] = b"GITSE";
/// Format version. v4 introduces the per-chunk AAD chain (anti-replay).
pub const VERSION: u8 = 4;
pub(super) const FLAG_COMPRESSED: u8 = 1 << 0;
pub(super) const ENC_ALGO: u8 = 1;

pub const SALT_LEN: usize = 16;
pub const FILE_ID_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
pub const HEADER_LEN: usize = 64;
/// Byte offset of `FILE_ID` inside the header: MAGIC(5) + V(1) + F(1) + A(1) + SALT(16).
pub(super) const FILE_ID_OFFSET: usize = 5 + 1 + 1 + 1 + SALT_LEN;
/// Byte length of a Poly1305 tag (the AAD chain link).
pub(super) const TAG_LEN: usize = 16;
/// AAD layout (v4): HEADER (64B) || `prev_tag` (16B) || `chunk_idx` (8B LE) || `is_last` (1B).
pub(super) const AAD_LEN: usize = HEADER_LEN + TAG_LEN + 8 + 1;
pub(super) const RESERVED_LEN: usize =
    HEADER_LEN - (MAGIC.len() + 1 + 1 + 1 + SALT_LEN + FILE_ID_LEN);

pub const CHUNK_SIZE: usize = 65536;

#[inline]
#[must_use]
pub const fn is_encrypted_version(v: u8) -> bool {
    v == VERSION
}

/// Format-level check whether `bytes` start with a well-formed GITSE header
/// (magic, supported version, known algorithm, zeroed reserved field).
///
/// This is a **format check, not a cryptographic authentication**: a crafted
/// file with a valid-looking header passes it. Without the password, nothing
/// stronger is possible; AEAD verification happens at decryption time.
#[must_use]
pub fn is_encrypted_header(bytes: &[u8]) -> bool {
    let Some(header_bytes) = bytes.get(..HEADER_LEN) else {
        return false;
    };
    // length checked above
    let header_bytes: &[u8; HEADER_LEN] = header_bytes.try_into().unwrap();
    FileHeader::from_bytes(header_bytes).is_ok_and(|header| header.reserved.iter().all(|&b| b == 0))
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileHeader {
    pub magic: [u8; 5],
    pub version: u8,
    pub flags: u8,
    pub enc_algo: u8,
    pub salt: [u8; SALT_LEN],
    pub file_id: [u8; FILE_ID_LEN],
    pub reserved: [u8; RESERVED_LEN],
}

const _: () = assert!(std::mem::size_of::<FileHeader>() == HEADER_LEN);
const _: () = assert!(std::mem::align_of::<FileHeader>() == 1);

impl FileHeader {
    #[must_use]
    pub const fn new(compressed: bool, salt: [u8; SALT_LEN], file_id: [u8; FILE_ID_LEN]) -> Self {
        let mut flags = 0u8;
        if compressed {
            flags |= FLAG_COMPRESSED;
        }
        Self {
            magic: *MAGIC,
            version: VERSION,
            flags,
            enc_algo: ENC_ALGO,
            salt,
            file_id,
            reserved: [0u8; RESERVED_LEN],
        }
    }

    #[must_use]
    pub fn generate_file_id() -> [u8; FILE_ID_LEN] {
        let mut rng = rand::rng();
        let mut id = [0u8; FILE_ID_LEN];
        rng.fill_bytes(&mut id);
        id
    }

    pub fn from_bytes(bytes: &[u8; HEADER_LEN]) -> crate::error::Result<&Self> {
        use crate::error::Error;

        let header: &Self = unsafe { &*(bytes.as_ptr().cast()) };

        if &header.magic != MAGIC {
            return Err(Error::InvalidMagic);
        }
        if !is_encrypted_version(header.version) {
            return Err(Error::UnsupportedVersion(header.version));
        }
        if header.enc_algo != ENC_ALGO {
            return Err(Error::UnsupportedAlgo(header.enc_algo));
        }

        Ok(header)
    }

    pub fn read_from<R: std::io::Read>(reader: &mut R) -> crate::error::Result<Self> {
        let mut buf = [0u8; HEADER_LEN];
        reader.read_exact(&mut buf)?;
        Ok(*Self::from_bytes(&buf)?)
    }

    pub fn write_to<W: std::io::Write>(&self, writer: &mut W) -> crate::error::Result<()> {
        writer.write_all(self.as_bytes())?;
        Ok(())
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HEADER_LEN] {
        unsafe { &*std::ptr::from_ref::<Self>(self).cast() }
    }

    #[must_use]
    pub const fn is_compressed(&self) -> bool {
        (self.flags & FLAG_COMPRESSED) != 0
    }
}
