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
/// Every flag bit this version understands. Unknown bits make a header
/// unusable: they would describe a body this build cannot interpret.
pub(super) const KNOWN_FLAGS: u8 = FLAG_COMPRESSED;

/// Smallest possible well-formed encrypted file.
///
/// The header plus one complete chunk. The encrypt loop always emits a final
/// (possibly empty) chunk, and an empty chunk still costs `[NONCE | TAG]`, so
/// nothing valid is ever shorter. This is what stops a bare 64-byte header
/// from passing as ciphertext.
pub const MIN_ENCRYPTED_LEN: usize = HEADER_LEN + NONCE_LEN + TAG_LEN;
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

/// Why a GITSE-looking file is not a valid v4 encrypted file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MalformedReason {
    /// The magic is there but the 64-byte header is cut short.
    TruncatedHeader,
    /// A format version this build does not implement.
    UnsupportedVersion,
    /// An encryption algorithm this build does not implement.
    UnsupportedAlgo,
    /// Flag bits this format version does not define are set.
    UnknownFlags,
    /// The reserved field carries data instead of zeroes.
    ReservedNotZero,
    /// Header is fine but no complete chunk follows it.
    NoCompleteChunk,
}

impl MalformedReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TruncatedHeader => "GITSE magic present but the 64-byte header is truncated",
            Self::UnsupportedVersion => "unsupported format version",
            Self::UnsupportedAlgo => "unsupported encryption algorithm",
            Self::UnknownFlags => "unknown header flag bits set",
            Self::ReservedNotZero => "header reserved field is not zero",
            Self::NoCompleteChunk => "header is not followed by a complete chunk",
        }
    }
}

impl std::fmt::Display for MalformedReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What [`probe_header`] concluded about a file's leading bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderProbe {
    /// A well-formed v4 header followed by at least one complete chunk.
    Encrypted,
    /// No GITSE magic — an ordinary file that still needs encrypting.
    Plaintext,
    /// GITSE magic is present but the rest does not describe a valid v4 file.
    /// Callers must refuse to act rather than guess: encrypting could destroy
    /// real ciphertext, skipping could leak real plaintext.
    Malformed(MalformedReason),
}

/// Format-probe the leading bytes of a file or blob.
///
/// `bytes` must be the first [`MIN_ENCRYPTED_LEN`] bytes of the file, or the
/// whole file when it is shorter — a short slice is what proves the file
/// cannot contain a complete chunk.
///
/// This is a **format check, not a cryptographic authentication**: without the
/// password nothing stronger is possible, and AEAD verification only happens
/// at decryption time. What it does guarantee is that every entry point
/// (encrypt's skip decision, `check`, `check --staged`) reaches the *same*
/// verdict, so a file can never be skipped by one and accepted by another.
#[must_use]
pub fn probe_header(bytes: &[u8]) -> HeaderProbe {
    if !bytes.starts_with(MAGIC) {
        return HeaderProbe::Plaintext;
    }
    let Some(header_bytes) = bytes.get(..HEADER_LEN) else {
        return HeaderProbe::Malformed(MalformedReason::TruncatedHeader);
    };
    // length checked above
    let header_bytes: &[u8; HEADER_LEN] = header_bytes.try_into().unwrap();
    if let Err(e) = FileHeader::from_bytes(header_bytes) {
        use crate::error::Error;
        return HeaderProbe::Malformed(match e {
            Error::UnsupportedVersion(_) => MalformedReason::UnsupportedVersion,
            Error::UnsupportedAlgo(_) => MalformedReason::UnsupportedAlgo,
            Error::UnknownHeaderFlags(_) => MalformedReason::UnknownFlags,
            _ => MalformedReason::ReservedNotZero,
        });
    }
    if bytes.len() < MIN_ENCRYPTED_LEN {
        return HeaderProbe::Malformed(MalformedReason::NoCompleteChunk);
    }
    HeaderProbe::Encrypted
}

/// Whether `bytes` start a well-formed encrypted file. See [`probe_header`]
/// for the exact contract on `bytes` — in particular it must span up to
/// [`MIN_ENCRYPTED_LEN`] bytes, not just the header.
#[must_use]
pub fn is_encrypted_header(bytes: &[u8]) -> bool {
    probe_header(bytes) == HeaderProbe::Encrypted
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
        // Unknown flag bits describe a body this build cannot interpret;
        // accepting them would let a crafted header pass as ciphertext (M-01).
        if header.flags & !KNOWN_FLAGS != 0 {
            return Err(Error::UnknownHeaderFlags(header.flags));
        }
        if !header.reserved.iter().all(|&b| b == 0) {
            return Err(Error::ReservedNotZero);
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
