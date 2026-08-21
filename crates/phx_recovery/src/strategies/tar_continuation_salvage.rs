//! TAR continuation salvage strategy — wires the exact-recovery `resync` track
//! into the auto-repair pipeline (Phase 6 engine).
//!
//! Stock `tar` stops at the first all-zero block (read as end-of-archive) and at
//! the first unreadable header. This strategy walks the whole stream, skipping
//! zero blocks and resyncing past corrupt headers (`--ignore-zeros`), and re-emits
//! every **ustar-checksum-verified** member's original bytes into a valid archive
//! with a fresh terminator. Members are byte-exact; the corrupt header's member is
//! dropped, never fabricated.
//!
//! Selection: fallback (below the surgical tar field-repairs) for a TAR with
//! corruption those repairs can't resolve. If no member verifies it produces
//! nothing and the engine falls through.

use phx_analyze_engine::model::{AnalysisResult, ArchiveFormat, Corruption};
use phx_analyze_engine::reader::DataSource;

use crate::model::{DataSink, RecoveryError, RecoveryReport};
use crate::plan::RepairRisk;
use crate::resync::{salvage_tar, SegmentKind};

use super::{read_all, RecoveryStrategy};

const BLOCK: usize = 512;

/// Recover the checksum-verified members of a TAR, continuing past zero blocks
/// and corrupt headers.
pub struct TarContinuationSalvage;

impl RecoveryStrategy for TarContinuationSalvage {
    fn name(&self) -> &str {
        "tar-continuation-salvage"
    }

    fn technique(&self) -> &'static str {
        "TarContinuationSalvage"
    }

    fn risk(&self) -> RepairRisk {
        RepairRisk::Lossy
    }

    fn handles(&self, c: &Corruption) -> bool {
        matches!(
            c.chain.primary.rule_id.as_str(),
            "TAR_UST_001" | "TAR_TERM_001"
        )
    }

    fn predicted_outcome(&self, _c: &Corruption) -> String {
        "recover every ustar-checksum-verified TAR member (ignore-zeros + header resync) \
         and re-emit them as a valid archive; drop unreadable members"
            .to_string()
    }

    fn can_apply(&self, result: &AnalysisResult) -> bool {
        result.archive_format == Some(ArchiveFormat::Tar) && !result.corruptions.is_empty()
    }

    fn priority(&self) -> u8 {
        45
    }

    fn apply(
        &self,
        source: &DataSource,
        output: &mut DataSink,
    ) -> Result<RecoveryReport, RecoveryError> {
        let data = read_all(source)?;
        let mut report = RecoveryReport::empty(Default::default());
        report.strategies_applied.push(self.name().to_string());

        let salvage = salvage_tar(&data);
        if salvage.members_verified == 0 {
            report.success = false;
            report.warnings.push(
                "no TAR member could be checksum-verified; nothing salvaged (falling through)"
                    .into(),
            );
            return Ok(report);
        }

        // Splice each verified member's ORIGINAL bytes, then a fresh terminator.
        let mut out = Vec::new();
        for seg in salvage
            .segments
            .iter()
            .filter(|s| s.kind == SegmentKind::VerifiedTarMember)
        {
            if let Some(slice) = data.get(seg.source_offset..seg.source_end) {
                out.extend_from_slice(slice);
            }
        }
        if out.is_empty() {
            report.success = false;
            return Ok(report);
        }
        // Pad to a 512-byte boundary (in case the last member's padding was short)
        // and append the two-block end-of-archive terminator.
        if out.len() % BLOCK != 0 {
            out.resize(out.len().div_ceil(BLOCK) * BLOCK, 0);
        }
        out.extend(std::iter::repeat_n(0u8, 2 * BLOCK));

        let kept = out.len() as u64;
        output.write(&out);
        report.bytes_recovered = kept;
        report.bytes_lost = (data.len() as u64).saturating_sub(kept);
        report.success = true;
        report.warnings.push(format!(
            "salvaged {} checksum-verified TAR member(s); re-emitted with a fresh terminator",
            salvage.members_verified
        ));
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::resync::build;

    #[test]
    fn auto_salvages_members_past_zero_block_and_corrupt_header() {
        let m1 = build::tar_member("a.txt", b"alpha body");
        let mut m2 = build::tar_member("b.txt", b"bravo body");
        m2[100] ^= 0xFF; // corrupt member 2 header → checksum fails
        let m3 = build::tar_member("c.txt", b"charlie body");
        let mut tar = Vec::new();
        tar.extend_from_slice(&m1);
        tar.extend_from_slice(&[0u8; BLOCK]); // premature zero block
        tar.extend_from_slice(&m2);
        tar.extend_from_slice(&m3);

        let src = DataSource::from_bytes(Path::new("x.tar"), tar);
        let mut sink = DataSink::new();
        let report = TarContinuationSalvage.apply(&src, &mut sink).unwrap();
        assert!(report.success);

        // The rebuilt archive contains a.txt and c.txt exactly; b.txt is dropped.
        let out = sink.as_bytes();
        assert_eq!(out.len() % BLOCK, 0);
        let salvaged = crate::resync::salvage_tar(out);
        let names: Vec<_> = salvaged
            .segments
            .iter()
            .filter_map(|s| s.name.clone())
            .collect();
        assert!(names.iter().any(|n| n == "a.txt"));
        assert!(names.iter().any(|n| n == "c.txt"));
        assert!(!names.iter().any(|n| n == "b.txt"));
        assert_eq!(salvaged.members_verified, 2);
    }

    /// End-to-end through the engine via forced selection: prove the strategy is
    /// wired into the recovery pipeline and its rebuilt archive is kept.
    #[test]
    fn engine_runs_forced_tar_continuation_salvage() {
        use crate::{RecoveryEngine, RecoveryOptions};

        let m1 = build::tar_member("a.txt", b"alpha body");
        let mut m2 = build::tar_member("b.txt", b"bravo body");
        m2[100] ^= 0xFF; // corrupt member 2 header
        let m3 = build::tar_member("c.txt", b"charlie body");
        let mut tar = Vec::new();
        tar.extend_from_slice(&m1);
        tar.extend_from_slice(&m2);
        tar.extend_from_slice(&m3);
        tar.extend_from_slice(&[0u8; 2 * BLOCK]);

        let options = RecoveryOptions {
            forced_strategy: Some("tar-continuation-salvage".to_string()),
            ..Default::default()
        };
        let (out, report) = RecoveryEngine::new()
            .recover_stream(&tar, Path::new("backup.tar"), &options)
            .expect("recover");

        let salvaged = crate::resync::salvage_tar(&out);
        assert_eq!(salvaged.members_verified, 2);
        assert!(report
            .strategies_applied
            .iter()
            .any(|s| s == "tar-continuation-salvage"));
    }
}
