//! Android `.ab` backup container: the ASCII header `adb backup`/`bmgr` write, wrapping an
//! optionally-DEFLATE-compressed, optionally-AES-256-encrypted TAR stream.
//!
//! Header line order and semantics verified against the reference implementation
//! (`AndroidBackup.java`, itself derived from AOSP's `BackupManagerService.java`):
//! <https://github.com/nelenkov/android-backup-extractor/blob/master/src/org/nick/abe/AndroidBackup.java>
//! Not guessed from memory — see `docs/ANDROID_EDITIONS_ROADMAP.md` §10.7 (Phase 1).
//!
//! Phase 1 scope: recognize the container and read the four header lines common to every
//! version — magic, version, compressed flag, encryption algorithm name — then, for an
//! *unencrypted* container only, decompress the payload if it is DEFLATE-compressed.
//!
//! Phase 2 (`ANDROID_EDITIONS_ROADMAP.md` §10.7, DEC-I) adds the five lines an encrypted header
//! carries — user salt, checksum salt, PBKDF2 rounds, user IV, wrapped master key blob, all parsed
//! here — but the key derivation and AES decryption themselves live in `phx_recovery`, which is not
//! wasm32-constrained the way this crate is (see the crate doc). Parsing an encrypted header never
//! requires a password; decrypting it does.

use std::io::Read;

use flate2::read::ZlibDecoder;

const MAGIC: &str = "ANDROID BACKUP";
const ENCRYPTION_NONE: &str = "none";
const ENCRYPTION_AES256: &str = "AES-256";
const SUPPORTED_VERSIONS: std::ops::RangeInclusive<u32> = 1..=5;
/// `PBKDF2_SALT_SIZE` in the reference implementation: 512 bits.
const USER_SALT_BYTES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndroidBackupHeader {
    pub version: u32,
    pub compressed: bool,
    pub encrypted: bool,
    /// Byte offset, from the start of the file, where this header ends. Only meaningful when
    /// `encrypted` is false — an encrypted container's real payload starts after
    /// [`EncryptedBackupFields`] instead; use [`AndroidBackupHeader::encrypted_fields`].
    pub payload_offset: usize,
    /// `Some` iff `encrypted` — the five additional header lines, hex-decoded where the reference
    /// format encodes them as hex.
    pub encrypted_fields: Option<EncryptedBackupFields>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedBackupFields {
    pub user_salt: Vec<u8>,
    pub checksum_salt: Vec<u8>,
    pub rounds: u32,
    pub user_iv: Vec<u8>,
    pub master_key_blob: Vec<u8>,
    /// Byte offset, from the start of the file, where the encrypted payload begins.
    pub payload_offset: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AndroidBackupRefusal {
    BadMagic,
    TruncatedHeader,
    UnsupportedVersion,
    MalformedField,
    /// A hex field didn't decode, or `user_salt` decoded to a length other than 64 bytes — the
    /// same check the reference reader performs before trusting the salt.
    MalformedEncryptedField,
}

/// Decodes a hex string exactly as the reference `hexToByteArray` does: even length required,
/// every character must be a hex digit. No partial output on failure.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Some(out)
}

/// Reads one `\n`-terminated ASCII line, matching the reference reader byte-for-byte: consumes
/// and discards the newline, returns `None` (truncated) if the stream ends before one is found.
fn next_line(data: &[u8], offset: &mut usize) -> Option<String> {
    let start = *offset;
    while *offset < data.len() && data[*offset] != b'\n' {
        *offset += 1;
    }
    if *offset >= data.len() {
        return None;
    }
    let line = std::str::from_utf8(&data[start..*offset]).ok()?.to_string();
    *offset += 1; // consume the newline
    Some(line)
}

pub fn parse_header(data: &[u8]) -> Result<AndroidBackupHeader, AndroidBackupRefusal> {
    let mut offset = 0usize;

    let magic = next_line(data, &mut offset).ok_or(AndroidBackupRefusal::TruncatedHeader)?;
    if magic != MAGIC {
        return Err(AndroidBackupRefusal::BadMagic);
    }

    let version_line = next_line(data, &mut offset).ok_or(AndroidBackupRefusal::TruncatedHeader)?;
    let version: u32 = version_line
        .parse()
        .map_err(|_| AndroidBackupRefusal::MalformedField)?;
    if !SUPPORTED_VERSIONS.contains(&version) {
        return Err(AndroidBackupRefusal::UnsupportedVersion);
    }

    let compressed_line =
        next_line(data, &mut offset).ok_or(AndroidBackupRefusal::TruncatedHeader)?;
    let compressed = match compressed_line.as_str() {
        "1" => true,
        "0" => false,
        _ => return Err(AndroidBackupRefusal::MalformedField),
    };

    let encryption_line =
        next_line(data, &mut offset).ok_or(AndroidBackupRefusal::TruncatedHeader)?;
    let encrypted = match encryption_line.as_str() {
        ENCRYPTION_NONE => false,
        ENCRYPTION_AES256 => true,
        _ => return Err(AndroidBackupRefusal::MalformedField),
    };

    if !encrypted {
        return Ok(AndroidBackupHeader {
            version,
            compressed,
            encrypted,
            payload_offset: offset,
            encrypted_fields: None,
        });
    }

    let user_salt_line =
        next_line(data, &mut offset).ok_or(AndroidBackupRefusal::TruncatedHeader)?;
    let user_salt =
        hex_decode(&user_salt_line).ok_or(AndroidBackupRefusal::MalformedEncryptedField)?;
    if user_salt.len() != USER_SALT_BYTES {
        return Err(AndroidBackupRefusal::MalformedEncryptedField);
    }

    let checksum_salt_line =
        next_line(data, &mut offset).ok_or(AndroidBackupRefusal::TruncatedHeader)?;
    let checksum_salt =
        hex_decode(&checksum_salt_line).ok_or(AndroidBackupRefusal::MalformedEncryptedField)?;

    let rounds_line = next_line(data, &mut offset).ok_or(AndroidBackupRefusal::TruncatedHeader)?;
    let rounds: u32 = rounds_line
        .parse()
        .map_err(|_| AndroidBackupRefusal::MalformedEncryptedField)?;

    let user_iv_line = next_line(data, &mut offset).ok_or(AndroidBackupRefusal::TruncatedHeader)?;
    let user_iv = hex_decode(&user_iv_line).ok_or(AndroidBackupRefusal::MalformedEncryptedField)?;

    let master_key_blob_line =
        next_line(data, &mut offset).ok_or(AndroidBackupRefusal::TruncatedHeader)?;
    let master_key_blob =
        hex_decode(&master_key_blob_line).ok_or(AndroidBackupRefusal::MalformedEncryptedField)?;

    Ok(AndroidBackupHeader {
        version,
        compressed,
        encrypted,
        payload_offset: offset,
        encrypted_fields: Some(EncryptedBackupFields {
            user_salt,
            checksum_salt,
            rounds,
            user_iv,
            master_key_blob,
            payload_offset: offset,
        }),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadError {
    /// The zlib stream failed to decompress at all — no partial output is kept or guessed at,
    /// the same "corrupt stream → total abstention" rule `opc_zip::inflate_bounded` already uses
    /// for ZIP entries. Bit-level DEFLATE resync is out of Phase 1's scope.
    CorruptCompressedStream,
    /// Decompressed past `max_bytes` — a zlib-bomb guard, not a real backup.
    DecompressedTooLarge,
}

/// Returns the plaintext TAR bytes for an *unencrypted* container: the raw payload if
/// `header.compressed` is false, or its zlib-inflated form (bounded by `max_bytes`) if true.
pub fn plaintext_tar_bytes(
    data: &[u8],
    header: &AndroidBackupHeader,
    max_bytes: usize,
) -> Result<Vec<u8>, PayloadError> {
    decompress_if_needed(&data[header.payload_offset..], header.compressed, max_bytes)
}

/// Shared by the unencrypted path above and `phx_recovery`'s encrypted path: `payload` is either
/// the raw file bytes after the header (unencrypted) or the already-decrypted plaintext
/// (encrypted) — either way, zlib-inflate it here if `compressed`, bounded by `max_bytes`.
pub fn decompress_if_needed(
    payload: &[u8],
    compressed: bool,
    max_bytes: usize,
) -> Result<Vec<u8>, PayloadError> {
    if !compressed {
        return Ok(payload.to_vec());
    }
    let mut decoder = ZlibDecoder::new(payload);
    let mut out = Vec::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        match decoder.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                if out.len() > max_bytes {
                    return Err(PayloadError::DecompressedTooLarge);
                }
            }
            Err(_) => return Err(PayloadError::CorruptCompressedStream),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn header_bytes(lines: &[&str], payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for line in lines {
            out.extend_from_slice(line.as_bytes());
            out.push(b'\n');
        }
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn parses_unencrypted_compressed_header() {
        let bytes = header_bytes(&["ANDROID BACKUP", "1", "1", "none"], b"payload");
        let header = parse_header(&bytes).unwrap();
        assert_eq!(header.version, 1);
        assert!(header.compressed);
        assert!(!header.encrypted);
        assert_eq!(header.payload_offset, bytes.len() - "payload".len());
    }

    /// Built with `.repeat()`, not hand-counted hex literals — a miscounted salt length would
    /// silently test the wrong thing.
    fn encrypted_header_lines() -> Vec<String> {
        vec![
            "ANDROID BACKUP".to_string(),
            "5".to_string(),
            "1".to_string(),
            "AES-256".to_string(),
            "ab".repeat(64), // user salt: 64 bytes
            "cd".repeat(8),  // checksum salt: 8 bytes
            "10000".to_string(),
            "11".repeat(16),        // user IV: 16 bytes (AES block size)
            "deadbeef".to_string(), // master key blob (ciphertext; short in this fixture)
        ]
    }

    fn header_bytes_owned(lines: &[String], payload: &[u8]) -> Vec<u8> {
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        header_bytes(&refs, payload)
    }

    #[test]
    fn parses_a_full_encrypted_header() {
        let lines = encrypted_header_lines();
        let bytes = header_bytes_owned(&lines, b"ciphertext-follows");
        let header = parse_header(&bytes).unwrap();
        assert!(header.encrypted);
        let fields = header.encrypted_fields.as_ref().unwrap();
        assert_eq!(fields.user_salt.len(), 64);
        assert_eq!(fields.checksum_salt.len(), 8);
        assert_eq!(fields.rounds, 10000);
        assert_eq!(fields.user_iv.len(), 16);
        assert_eq!(fields.master_key_blob, vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(
            fields.payload_offset,
            bytes.len() - "ciphertext-follows".len()
        );
    }

    #[test]
    fn refuses_an_encrypted_header_with_a_wrong_length_user_salt() {
        let mut lines = encrypted_header_lines();
        lines[4] = "aabb".to_string(); // far short of the required 64 bytes
        assert_eq!(
            parse_header(&header_bytes_owned(&lines, b"")),
            Err(AndroidBackupRefusal::MalformedEncryptedField)
        );
    }

    #[test]
    fn refuses_an_encrypted_header_with_non_hex_or_truncated_fields() {
        let mut bad_hex = encrypted_header_lines();
        bad_hex[5] = "zz".to_string(); // not hex
        assert_eq!(
            parse_header(&header_bytes_owned(&bad_hex, b"")),
            Err(AndroidBackupRefusal::MalformedEncryptedField)
        );

        let truncated = &encrypted_header_lines()[..7]; // stops mid-way through the encrypted fields
        assert_eq!(
            parse_header(&header_bytes_owned(truncated, b"")),
            Err(AndroidBackupRefusal::TruncatedHeader)
        );
    }

    #[test]
    fn rejects_bad_magic_out_of_range_version_and_malformed_fields() {
        assert_eq!(
            parse_header(&header_bytes(&["NOPE", "1", "1", "none"], b"")),
            Err(AndroidBackupRefusal::BadMagic)
        );
        assert_eq!(
            parse_header(&header_bytes(&["ANDROID BACKUP", "6", "1", "none"], b"")),
            Err(AndroidBackupRefusal::UnsupportedVersion)
        );
        assert_eq!(
            parse_header(&header_bytes(&["ANDROID BACKUP", "1", "9", "none"], b"")),
            Err(AndroidBackupRefusal::MalformedField)
        );
        assert_eq!(
            parse_header(b"ANDROID BACKUP\n1\n1"),
            Err(AndroidBackupRefusal::TruncatedHeader)
        );
    }

    #[test]
    fn plaintext_tar_bytes_passes_through_uncompressed_payload() {
        let bytes = header_bytes(&["ANDROID BACKUP", "1", "0", "none"], b"raw tar bytes");
        let header = parse_header(&bytes).unwrap();
        let out = plaintext_tar_bytes(&bytes, &header, 1024).unwrap();
        assert_eq!(out, b"raw tar bytes");
    }

    #[test]
    fn plaintext_tar_bytes_inflates_a_zlib_stream() {
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(b"hello tar payload").unwrap();
        let compressed = enc.finish().unwrap();
        let mut bytes = header_bytes(&["ANDROID BACKUP", "2", "1", "none"], &[]);
        bytes.extend_from_slice(&compressed);
        let header = parse_header(&bytes).unwrap();
        let out = plaintext_tar_bytes(&bytes, &header, 1024).unwrap();
        assert_eq!(out, b"hello tar payload");
    }

    #[test]
    fn plaintext_tar_bytes_refuses_a_corrupt_zlib_stream_rather_than_guessing() {
        let bytes = header_bytes(
            &["ANDROID BACKUP", "1", "1", "none"],
            b"not zlib data at all",
        );
        let header = parse_header(&bytes).unwrap();
        assert_eq!(
            plaintext_tar_bytes(&bytes, &header, 1024),
            Err(PayloadError::CorruptCompressedStream)
        );
    }

    #[test]
    fn plaintext_tar_bytes_enforces_the_bomb_guard() {
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        enc.write_all(&vec![0u8; 1024]).unwrap();
        let compressed = enc.finish().unwrap();
        let mut bytes = header_bytes(&["ANDROID BACKUP", "1", "1", "none"], &[]);
        bytes.extend_from_slice(&compressed);
        let header = parse_header(&bytes).unwrap();
        assert_eq!(
            plaintext_tar_bytes(&bytes, &header, 16),
            Err(PayloadError::DecompressedTooLarge)
        );
    }
}
