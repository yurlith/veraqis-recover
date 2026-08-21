//! Bounds for ZIP recovery walks — the limits that replace a damaged file's own numbers.
//!
//! A damaged archive's declared counts, sizes and offsets are **untrusted hints**. They cannot be
//! the bound on how much work the parser does, because the whole point of recovery is that they
//! may be wrong; and they cannot be *ignored* either, because then a hostile file decides how long
//! we run. So the bounds come from here: explicit, versioned, and independent of the file.
//!
//! This replaces a bare `max_entries.clamp(1, 1_000_000)`, which was two bugs in one expression.
//! The `1` floor let an EOCD count of zero cap a physically intact directory at a single record
//! (F-3), and the `1_000_000` ceiling was an undocumented magic number that no caller could see,
//! tune or reason about.
//!
//! Every limit answers one question: *what would an attacker or a corrupt file have to claim to
//! make us do unbounded work?* Each is checked against the **physical** source, never against a
//! number read out of the damaged file.

/// Schema version of this policy. Bump when a field's meaning changes, not when a default moves.
pub const ZIP_RECOVERY_POLICY_VERSION: u32 = 1;

/// Why a walk stopped early. Distinguishes "the archive ended" from "we refused to keep going",
/// which the caller must be able to tell apart: the first is a fact about the file, the second is
/// a fact about us, and only the second means the report is incomplete for our own reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitHit {
    /// `max_central_records` reached while records were still well-formed.
    CentralRecords,
    /// `max_central_bytes` of directory region consumed.
    CentralBytes,
    /// `max_candidate_records` local-header candidates accepted.
    CandidateRecords,
    /// `max_scan_bytes` of source examined by the local-header scan.
    ScanBytes,
    /// `max_metadata_bytes` of names/extra/comments accumulated.
    MetadataBytes,
    /// `max_malformed_streak` consecutive rejected candidates.
    MalformedStreak,
}

impl LimitHit {
    /// Stable code for reports and tests. Never renamed without a migration.
    pub fn code(self) -> &'static str {
        match self {
            LimitHit::CentralRecords => "CENTRAL_DIRECTORY_WALK_LIMIT_REACHED",
            LimitHit::CentralBytes => "CENTRAL_DIRECTORY_BYTE_LIMIT_REACHED",
            LimitHit::CandidateRecords => "LOCAL_HEADER_SCAN_LIMIT_REACHED",
            LimitHit::ScanBytes => "LOCAL_HEADER_SCAN_BYTE_LIMIT_REACHED",
            LimitHit::MetadataBytes => "METADATA_ALLOCATION_LIMIT_REACHED",
            LimitHit::MalformedStreak => "MALFORMED_RECORD_STREAK_LIMIT_REACHED",
        }
    }
}

/// Hard bounds for a recovery walk. Independent of anything the archive declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZipRecoveryPolicy {
    /// Most central-directory records to accept. A real archive with more than this is beyond
    /// what this recovery path is for; the walk stops and says so rather than pretending.
    pub max_central_records: usize,
    /// Most bytes of central-directory region to walk.
    pub max_central_bytes: usize,
    /// Most local-header candidates to accept from a scan.
    pub max_candidate_records: usize,
    /// Most source bytes the local-header scan may examine.
    pub max_scan_bytes: usize,
    /// Most bytes of names + extra fields + comments to retain across all records. This is the
    /// allocation bound: a file can declare 65 535 bytes of name per record, so the per-record
    /// limits alone do not bound total memory.
    pub max_metadata_bytes: usize,
    /// Consecutive malformed/rejected records before a walk gives up. Guards against grinding
    /// through megabytes of payload that merely looks like headers.
    pub max_malformed_streak: usize,
    /// Longest single entry name to retain.
    pub max_name_bytes: usize,
    /// Longest single extra field to inspect.
    pub max_extra_bytes: usize,
    /// Longest single comment to skip over.
    pub max_comment_bytes: usize,
    /// Most segments a piecewise offset map may contain. A single edit needs two; a few more
    /// leaves room for two edits. Beyond that the file is not describing an edit history.
    pub max_offset_segments: usize,
}

impl Default for ZipRecoveryPolicy {
    fn default() -> Self {
        Self {
            // 262 144 records at ~46 B of fixed header each is ~12 MB of directory — far past any
            // archive this path is meant for, and small enough that the walk cannot become the
            // denial of service.
            max_central_records: 262_144,
            max_central_bytes: 128 * 1024 * 1024,
            max_candidate_records: 262_144,
            max_scan_bytes: 2 * 1024 * 1024 * 1024,
            max_metadata_bytes: 64 * 1024 * 1024,
            // A run of rejects this long means we are walking payload, not structure.
            max_malformed_streak: 4096,
            // ZIP's own field widths are 16-bit; these are the format maxima, not guesses.
            max_name_bytes: 65_535,
            max_extra_bytes: 65_535,
            max_comment_bytes: 65_535,
            max_offset_segments: 4,
        }
    }
}

impl ZipRecoveryPolicy {
    /// Reject a policy that cannot make progress or that removes a bound entirely.
    ///
    /// A zero limit is not "unlimited" here — it is a policy that can accept nothing, which is
    /// almost certainly a construction mistake rather than an intent. Saying so at construction
    /// is better than returning an empty recovery that looks like a clean archive.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.max_central_records == 0 {
            return Err("max_central_records must be > 0");
        }
        if self.max_candidate_records == 0 {
            return Err("max_candidate_records must be > 0");
        }
        if self.max_central_bytes == 0 || self.max_scan_bytes == 0 {
            return Err("byte limits must be > 0");
        }
        if self.max_metadata_bytes == 0 {
            return Err("max_metadata_bytes must be > 0");
        }
        if self.max_malformed_streak == 0 {
            return Err("max_malformed_streak must be > 0");
        }
        if self.max_name_bytes == 0 {
            return Err("max_name_bytes must be > 0");
        }
        Ok(())
    }

    /// A deliberately tiny policy, for tests that need to observe a limit being hit.
    pub fn tiny() -> Self {
        Self {
            max_central_records: 4,
            max_central_bytes: 4096,
            max_candidate_records: 4,
            max_scan_bytes: 4096,
            max_metadata_bytes: 4096,
            max_malformed_streak: 16,
            max_name_bytes: 256,
            max_extra_bytes: 256,
            max_comment_bytes: 256,
            max_offset_segments: 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_is_valid() {
        assert!(ZipRecoveryPolicy::default().validate().is_ok());
        assert!(ZipRecoveryPolicy::tiny().validate().is_ok());
    }

    #[test]
    fn a_zero_limit_is_rejected_rather_than_read_as_unlimited() {
        let p = ZipRecoveryPolicy {
            max_central_records: 0,
            ..ZipRecoveryPolicy::default()
        };
        assert!(p.validate().is_err());

        let p = ZipRecoveryPolicy {
            max_metadata_bytes: 0,
            ..ZipRecoveryPolicy::default()
        };
        assert!(p.validate().is_err());

        let p = ZipRecoveryPolicy {
            max_malformed_streak: 0,
            ..ZipRecoveryPolicy::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn limit_codes_are_stable_and_distinct() {
        let all = [
            LimitHit::CentralRecords,
            LimitHit::CentralBytes,
            LimitHit::CandidateRecords,
            LimitHit::ScanBytes,
            LimitHit::MetadataBytes,
            LimitHit::MalformedStreak,
        ];
        let mut codes: Vec<&str> = all.iter().map(|l| l.code()).collect();
        codes.sort_unstable();
        let before = codes.len();
        codes.dedup();
        assert_eq!(before, codes.len(), "limit codes must be distinct");
        assert_eq!(
            LimitHit::CentralRecords.code(),
            "CENTRAL_DIRECTORY_WALK_LIMIT_REACHED"
        );
    }
}
