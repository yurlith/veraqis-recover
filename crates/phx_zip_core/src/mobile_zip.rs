//! Narrow mobile P0 seam for recovering fully-present ZIP entries.
//!
//! This is orchestration over the existing recovery-oriented OPC ZIP reader. It adds no second ZIP
//! parser: local-header discovery, bounded inflate and independent CRC verification remain owned by
//! [`crate::opc_zip`]. Only CRC-verified bytes with a safe relative path are returned.

use std::collections::HashSet;

use crate::opc_zip::{extract_entry, parse_zip, ExtractStatus};
use crate::verdict::{CdProvenance, RecoveryVerdict};

#[derive(Debug, Clone, Copy)]
pub struct MobileZipLimits {
    pub max_entries: usize,
    pub max_entry_bytes: u64,
    pub max_total_bytes: u64,
    pub max_path_bytes: usize,
    pub max_depth: usize,
}

impl Default for MobileZipLimits {
    fn default() -> Self {
        Self {
            max_entries: 10_000,
            // The underlying recovery reader has the same 512 MiB bounded-inflate ceiling.
            max_entry_bytes: 512 * 1024 * 1024,
            max_total_bytes: 8 * 1024 * 1024 * 1024,
            max_path_bytes: 240,
            max_depth: 24,
        }
    }
}

#[derive(Debug)]
pub struct MobileZipEntry {
    pub safe_path: String,
    pub bytes: Vec<u8>,
    pub crc32: u32,
    /// Always [`RecoveryVerdict::ExactRecoverable`]: this seam emits an entry only after its
    /// decoded bytes match a CRC-32 that survived in the archive, independent of any repair.
    pub verdict: RecoveryVerdict,
}

#[derive(Debug)]
pub struct MobileZipSkipped {
    pub name: String,
    pub reason: &'static str,
    /// Why the caller may not present this entry: bytes existed but nothing proved them
    /// ([`RecoveryVerdict::SalvagedUnverified`]), or nothing could be produced at all
    /// ([`RecoveryVerdict::Unrecoverable`]).
    pub verdict: RecoveryVerdict,
}

impl MobileZipSkipped {
    fn new(name: String, reason: &'static str) -> Self {
        // `crc_mismatch` is the one abstention where bytes were actually decoded — they are
        // simply unproven. Everything else produced nothing usable at all.
        let verdict = if reason == "crc_mismatch" {
            RecoveryVerdict::SalvagedUnverified
        } else {
            RecoveryVerdict::Unrecoverable
        };
        Self {
            name,
            reason,
            verdict,
        }
    }
}

#[derive(Debug)]
pub struct MobileZipRecovery {
    pub used_local_scan: bool,
    pub central_directory_found: bool,
    pub entries_seen: usize,
    pub entries: Vec<MobileZipEntry>,
    pub skipped: Vec<MobileZipSkipped>,
    pub warnings: Vec<String>,
}

#[derive(Debug)]
pub struct MobileZipRecoverySummary {
    pub used_local_scan: bool,
    pub central_directory_found: bool,
    pub entries_seen: usize,
    pub entries: Vec<MobileZipEntrySummary>,
    pub skipped: Vec<MobileZipSkipped>,
    pub warnings: Vec<String>,
}

#[derive(Debug)]
pub struct MobileZipEntrySummary {
    pub safe_path: String,
    pub bytes: u64,
    pub crc32: u32,
    pub verdict: RecoveryVerdict,
}

/// Recover only fully-present, independently CRC-verified entries.
///
/// `Unknown`/abstention is represented by a skipped entry. No bytes from a failed, encrypted,
/// unsupported, truncated, over-limit or path-unsafe entry are returned.
pub fn recover_verified_entries(
    data: &[u8],
    limits: MobileZipLimits,
    cd_provenance: CdProvenance,
) -> MobileZipRecovery {
    let mut entries = Vec::new();
    let summary = recover_verified_entries_to(data, limits, cd_provenance, |entry| {
        entries.push(entry);
        Ok(())
    })
    .expect("the in-memory collector is infallible");
    MobileZipRecovery {
        used_local_scan: summary.used_local_scan,
        central_directory_found: summary.central_directory_found,
        entries_seen: summary.entries_seen,
        entries,
        skipped: summary.skipped,
        warnings: summary.warnings,
    }
}

/// Recover verified entries one at a time into a caller-owned sink.
///
/// This is the bounded-memory mobile path: at most one decoded entry is resident at a time, and
/// the sink can persist it before the next entry is decoded. The ZIP parsing and CRC decision are
/// identical to [`recover_verified_entries`].
pub fn recover_verified_entries_to<F>(
    data: &[u8],
    limits: MobileZipLimits,
    cd_provenance: CdProvenance,
    mut emit: F,
) -> Result<MobileZipRecoverySummary, String>
where
    F: FnMut(MobileZipEntry) -> Result<(), String>,
{
    let parsed = parse_zip(data);

    // Can this archive's directory speak about what is NOT in it? Only if it is an independent
    // witness (not one PHX rebuilt from these very headers — E1/DEC-016) and it is complete: its
    // declared count matches the records walked. See the F-2B guard below.
    let directory_enumerates_archive =
        parsed.cd_count_consistent && cd_provenance.attests_existence();

    let mut recovered = Vec::new();
    let mut skipped = Vec::new();
    let mut total = 0u64;
    let mut names = HashSet::new();

    for entry in parsed.entries.iter().take(limits.max_entries) {
        if !entry.name_valid_utf8 {
            skipped.push(MobileZipSkipped::new(
                entry.name.clone(),
                "invalid_utf8_path",
            ));
            continue;
        }
        if entry.name.ends_with('/') || entry.name.ends_with('\\') {
            skipped.push(MobileZipSkipped::new(entry.name.clone(), "directory"));
            continue;
        }
        let Some(safe_path) =
            safe_relative_path(&entry.name, limits.max_path_bytes, limits.max_depth)
        else {
            skipped.push(MobileZipSkipped::new(entry.name.clone(), "unsafe_path"));
            continue;
        };
        if !names.insert(safe_path.to_lowercase()) {
            skipped.push(MobileZipSkipped::new(entry.name.clone(), "duplicate_path"));
            continue;
        }
        if entry.uncomp_size > limits.max_entry_bytes {
            skipped.push(MobileZipSkipped::new(entry.name.clone(), "entry_limit"));
            continue;
        }

        let extracted = extract_entry(data, entry);
        if extracted.status != ExtractStatus::VerifiedCrc {
            skipped.push(MobileZipSkipped::new(
                entry.name.clone(),
                status_reason(extracted.status),
            ));
            continue;
        }
        // A zero-length entry found only by a local-header scan carries no evidence at all:
        // CRC-32 of nothing is 0 by definition, so the check is satisfied by construction and
        // contributes zero bits (CLAUDE.md, Evidence model — a result with `evidence_bits = 0`
        // and no exact-erasure basis may not be emitted). A planted `PK\x03\x04` header naming a
        // file that never existed passes it, which is how a scanner is made to invent an entry.
        // A central-directory record is independent corroboration that the entry is real, so
        // empty files in an archive with a readable directory are still recovered.
        //
        // E1: the directory record only corroborates when the directory itself is an independent
        // witness. A directory PHX rebuilt from these very local headers is derived from the thing
        // it would attest, so it carries zero weight here (DEC-016 §5/§6) — otherwise repairing an
        // archive would manufacture the evidence that launders a planted entry into a recovered one.
        let cd_attests = cd_provenance.entry_is_attested(entry.from_central_dir);

        // F-2B: the non-empty sibling of the guard below.
        //
        // A planted local header carrying a correct CRC-32 over its own payload passes every
        // check the payload can offer, because the payload and the checksum were written
        // together. The checksum proves the bytes match THAT HEADER; it says nothing about
        // whether the header ever belonged to this archive. Its evidence about *existence* is
        // zero bits, and emitting it is how a scanner is made to invent a file.
        //
        // The independent witness to existence is a complete central directory. "Complete" is
        // load-bearing and is measured, not assumed: the EOCD's declared count must agree with
        // the number of records actually walked. Only then does the directory enumerate every
        // entry the archive claims to have, and only then is its silence a denial.
        //
        // When the directory is missing or known-incomplete — the `cd-missing` class the product
        // is positioned on — its silence proves nothing, and refusing scan-only entries there
        // would discard exactly the recovery customers come for. So the guard is conditional on
        // the directory being able to speak, never on it merely existing.
        if !cd_attests && directory_enumerates_archive {
            skipped.push(MobileZipSkipped::new(
                entry.name.clone(),
                "unattested_by_complete_directory",
            ));
            continue;
        }

        if extracted.bytes.is_empty() && !cd_attests {
            skipped.push(MobileZipSkipped::new(
                entry.name.clone(),
                "zero_length_unattested",
            ));
            continue;
        }
        let byte_len = extracted.bytes.len() as u64;
        if byte_len > limits.max_entry_bytes
            || total
                .checked_add(byte_len)
                .is_none_or(|next| next > limits.max_total_bytes)
        {
            skipped.push(MobileZipSkipped::new(entry.name.clone(), "total_limit"));
            continue;
        }
        total += byte_len;
        let recovered_entry = MobileZipEntry {
            safe_path,
            bytes: extracted.bytes,
            crc32: extracted.crc_actual,
            // Reached only through `ExtractStatus::VerifiedCrc`: the decoded bytes matched a
            // CRC-32 that survived in the archive rather than one any repair wrote.
            verdict: RecoveryVerdict::ExactRecoverable,
        };
        let summary = MobileZipEntrySummary {
            safe_path: recovered_entry.safe_path.clone(),
            bytes: recovered_entry.bytes.len() as u64,
            crc32: recovered_entry.crc32,
            verdict: recovered_entry.verdict,
        };
        emit(recovered_entry)?;
        recovered.push(summary);
    }

    if parsed.entries.len() > limits.max_entries {
        skipped.push(MobileZipSkipped::new(String::new(), "entry_count_limit"));
    }

    Ok(MobileZipRecoverySummary {
        used_local_scan: parsed.used_local_scan,
        central_directory_found: parsed.cd_found,
        entries_seen: parsed.entries.len(),
        entries: recovered,
        skipped,
        warnings: parsed.warnings,
    })
}

/// Shared by every mobile-P0 recovery seam, not just ZIP: `phx_recovery::mobile_tar` (Android
/// `.ab` backup recovery, `ANDROID_EDITIONS_ROADMAP.md` §10.7) holds TAR member names to the
/// exact same rules rather than a second, independently-maintained path-safety check.
pub fn safe_relative_path(raw: &str, max_bytes: usize, max_depth: usize) -> Option<String> {
    if raw.is_empty()
        || raw.len() > max_bytes
        || raw.contains('\0')
        || raw.starts_with('/')
        || raw.starts_with('\\')
    {
        return None;
    }
    let normalized = raw.replace('\\', "/");
    if normalized.as_bytes().get(1) == Some(&b':') {
        return None;
    }
    let parts: Vec<_> = normalized
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    if parts.is_empty()
        || parts.len() > max_depth
        || parts
            .iter()
            .any(|part| *part == "." || *part == ".." || part.contains(':'))
    {
        return None;
    }
    Some(parts.join("/"))
}

fn status_reason(status: ExtractStatus) -> &'static str {
    match status {
        ExtractStatus::VerifiedCrc => "verified",
        ExtractStatus::CrcMismatch => "crc_mismatch",
        ExtractStatus::DecodeFailed => "decode_failed",
        ExtractStatus::BadLocalHeader => "bad_local_header",
        ExtractStatus::Truncated => "truncated",
        ExtractStatus::Unsupported(_) => "unsupported_method",
        ExtractStatus::Encrypted => "encrypted",
        ExtractStatus::Zip64Unsupported => "zip64_unsupported",
        ExtractStatus::StreamedUnsized => "streamed_unsized",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Crc;

    fn stored_zip(name: &str, body: &[u8], include_central_directory: bool) -> Vec<u8> {
        let mut crc = Crc::new();
        crc.update(body);
        let checksum = crc.sum();
        let name_bytes = name.as_bytes();
        let mut out = Vec::new();
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&checksum.to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(body);
        if !include_central_directory {
            return out;
        }
        let cd_offset = out.len() as u32;
        out.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&checksum.to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(name_bytes);
        let cd_size = out.len() as u32 - cd_offset;
        out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    #[test]
    fn recovers_crc_verified_entry_without_central_directory() {
        let zip = stored_zip("docs/report.txt", b"verified", false);
        let result = recover_verified_entries(
            &zip,
            MobileZipLimits::default(),
            CdProvenance::OriginalSurviving,
        );
        assert!(result.used_local_scan);
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].safe_path, "docs/report.txt");
        assert_eq!(result.entries[0].bytes, b"verified");
    }

    #[test]
    fn abstains_on_crc_mismatch() {
        let mut zip = stored_zip("report.txt", b"verified", false);
        *zip.last_mut().unwrap() ^= 0xff;
        let result = recover_verified_entries(
            &zip,
            MobileZipLimits::default(),
            CdProvenance::OriginalSurviving,
        );
        assert!(result.entries.is_empty());
        assert_eq!(result.skipped[0].reason, "crc_mismatch");
    }

    #[test]
    fn abstains_on_traversal_path() {
        let zip = stored_zip("../private.txt", b"secret", false);
        let result = recover_verified_entries(
            &zip,
            MobileZipLimits::default(),
            CdProvenance::OriginalSurviving,
        );
        assert!(result.entries.is_empty());
        assert_eq!(result.skipped[0].reason, "unsafe_path");
    }

    #[test]
    fn uses_central_directory_when_present() {
        let zip = stored_zip("report.txt", b"verified", true);
        let result = recover_verified_entries(
            &zip,
            MobileZipLimits::default(),
            CdProvenance::OriginalSurviving,
        );
        assert!(!result.used_local_scan);
        assert!(result.central_directory_found);
        assert_eq!(result.entries.len(), 1);
    }

    #[test]
    fn abstains_on_invalid_utf8_path() {
        let mut zip = stored_zip("x.txt", b"verified", false);
        zip[30] = 0xff;
        let result = recover_verified_entries(
            &zip,
            MobileZipLimits::default(),
            CdProvenance::OriginalSurviving,
        );
        assert!(result.entries.is_empty());
        assert_eq!(result.skipped[0].reason, "invalid_utf8_path");
    }

    #[test]
    fn abstains_on_directory_entry() {
        let zip = stored_zip("docs/", b"", false);
        let result = recover_verified_entries(
            &zip,
            MobileZipLimits::default(),
            CdProvenance::OriginalSurviving,
        );
        assert!(result.entries.is_empty());
        assert_eq!(result.skipped[0].reason, "directory");
    }

    /// A syntactically valid local file header for a zero-length file that does not exist.
    /// Its CRC-32 field is 0, which the CRC of an empty payload matches by construction.
    fn planted_empty_header(name: &str) -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        h.extend_from_slice(&20u16.to_le_bytes());
        h.extend_from_slice(&0u16.to_le_bytes()); // flags
        h.extend_from_slice(&0u16.to_le_bytes()); // stored
        h.extend_from_slice(&0u16.to_le_bytes());
        h.extend_from_slice(&0u16.to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes()); // crc of nothing
        h.extend_from_slice(&0u32.to_le_bytes()); // compressed size
        h.extend_from_slice(&0u32.to_le_bytes()); // uncompressed size
        h.extend_from_slice(&(name.len() as u16).to_le_bytes());
        h.extend_from_slice(&0u16.to_le_bytes());
        h.extend_from_slice(name.as_bytes());
        h
    }

    #[test]
    fn a_planted_zero_length_header_is_not_emitted_from_a_scan() {
        // Without a usable central directory the reader scans local headers, and a planted
        // zero-length header would otherwise "verify" against a CRC that proves nothing.
        let mut zip = stored_zip("real.txt", b"genuine", false);
        zip.extend_from_slice(&planted_empty_header("ghost.txt"));

        let result = recover_verified_entries(
            &zip,
            MobileZipLimits::default(),
            CdProvenance::OriginalSurviving,
        );
        assert!(result.used_local_scan);
        assert!(
            result.entries.iter().all(|e| e.safe_path != "ghost.txt"),
            "an invented entry must never be emitted"
        );
        assert!(result
            .skipped
            .iter()
            .any(|s| s.name == "ghost.txt" && s.reason == "zero_length_unattested"));
        // The genuine entry beside it is still recovered.
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].safe_path, "real.txt");
    }

    #[test]
    fn a_genuine_empty_file_is_still_recovered_when_the_directory_attests_it() {
        let zip = stored_zip("empty.txt", b"", true);
        let result = recover_verified_entries(
            &zip,
            MobileZipLimits::default(),
            CdProvenance::OriginalSurviving,
        );
        assert!(result.central_directory_found);
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].safe_path, "empty.txt");
        assert!(result.entries[0].bytes.is_empty());
    }

    #[test]
    fn bounded_sink_receives_one_entry_at_a_time() {
        let zip = stored_zip("docs/report.txt", b"verified", false);
        let mut emitted = Vec::new();
        let summary = recover_verified_entries_to(
            &zip,
            MobileZipLimits::default(),
            CdProvenance::OriginalSurviving,
            |entry| {
                emitted.push((entry.safe_path, entry.bytes));
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(summary.entries.len(), 1);
        assert_eq!(
            emitted,
            vec![("docs/report.txt".to_string(), b"verified".to_vec())]
        );
    }
}
