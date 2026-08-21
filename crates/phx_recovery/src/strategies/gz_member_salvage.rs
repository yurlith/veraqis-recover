//! GZIP multi-member salvage strategy — wires the exact-recovery `resync` track
//! into the auto-repair pipeline (Phase 6 engine).
//!
//! A `.gz` is a concatenation of members, each ending in a CRC32+ISIZE trailer.
//! Stock `gunzip` aborts at the first corrupt member, losing every intact member
//! after it. This strategy recovers the **CRC-verified members' content** and
//! re-emits it as a single clean GZIP member, dropping only the corrupt member.
//! Every recovered byte is CRC32+ISIZE-proven content — never fabricated; the
//! re-wrap is lossless (same approach as `GzPartialInflate`). Re-wrapping as one
//! member also lets the (single-member) analyzer score the output as healthy.
//!
//! Selection: ranked above `GzTrailerRecompute` so a genuine multi-member salvage
//! is preferred over a single-member trailer fix — but it **abstains** (produces
//! nothing → the engine falls through) unless it CRC-verifies at least one member,
//! so it never preempts the surgical repairs on an ordinary single-member gzip.

use std::io::Write;

use phx_analyze_engine::model::{AnalysisResult, ArchiveFormat, Corruption};
use phx_analyze_engine::reader::DataSource;

use crate::model::{DataSink, RecoveryError, RecoveryReport};
use crate::plan::RepairRisk;
use crate::resync::salvage_gzip;

use super::{read_all, RecoveryStrategy};

/// Recover the CRC-verified members of a multi-member GZIP, dropping the corrupt one.
pub struct GzMemberSalvage;

impl RecoveryStrategy for GzMemberSalvage {
    fn name(&self) -> &str {
        "gz-member-salvage"
    }

    fn technique(&self) -> &'static str {
        "GzMemberSalvage"
    }

    fn risk(&self) -> RepairRisk {
        // Verified members are byte-exact, but the corrupt member is dropped.
        RepairRisk::Lossy
    }

    fn handles(&self, c: &Corruption) -> bool {
        matches!(
            c.chain.primary.rule_id.as_str(),
            "GZ_TRUNC_001" | "GZ_TRUNC_002" | "GZ_ICRC_001" | "GZ_ISIZE_001"
        )
    }

    fn predicted_outcome(&self, _c: &Corruption) -> String {
        "recover every CRC32+ISIZE-verified GZIP member and re-emit them as a valid .gz; \
         drop the corrupt member"
            .to_string()
    }

    fn can_apply(&self, result: &AnalysisResult) -> bool {
        result.archive_format == Some(ArchiveFormat::Gzip) && !result.corruptions.is_empty()
    }

    fn priority(&self) -> u8 {
        // Above GzTrailerRecompute (82): on a *multi-member* gzip, trailer
        // recompute only "fixes" the final trailer (single-member assumption) and
        // leaves a corrupt member in place. This strategy is safe to rank first
        // because it ABSTAINS (produces nothing → engine falls through) unless it
        // CRC-verifies ≥1 member — so it only preempts on a genuine member salvage.
        84
    }

    fn apply(
        &self,
        source: &DataSource,
        output: &mut DataSink,
    ) -> Result<RecoveryReport, RecoveryError> {
        let data = read_all(source)?;
        let mut report = RecoveryReport::empty(Default::default());
        report.strategies_applied.push(self.name().to_string());

        let salvage = salvage_gzip(&data);
        if salvage.members_verified == 0 {
            report.success = false;
            report.warnings.push(
                "no GZIP member could be CRC-verified; nothing salvaged (falling through)".into(),
            );
            return Ok(report);
        }

        // The exact, CRC-verified content of every intact member, in order.
        let content = salvage.verified_payload();
        if content.is_empty() {
            report.success = false;
            return Ok(report);
        }

        // Re-wrap the verified content as a single clean GZIP member (lossless).
        let mut out = Vec::new();
        {
            let mut enc = flate2::write::GzEncoder::new(&mut out, flate2::Compression::default());
            if enc
                .write_all(&content)
                .and_then(|_| enc.finish().map(|_| ()))
                .is_err()
            {
                report.success = false;
                report
                    .warnings
                    .push("re-encoding salvaged GZIP content failed".into());
                return Ok(report);
            }
        }

        output.write(&out);
        report.bytes_recovered = content.len() as u64;
        report.bytes_lost = salvage.unverified_bytes;
        report.success = true;
        report.warnings.push(format!(
            "salvaged {} CRC-verified GZIP member(s) ({} B exact content); \
             dropped the corrupt member, re-wrapped as one clean member",
            salvage.members_verified,
            content.len()
        ));
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::path::Path;

    use super::*;
    use crate::resync::build;

    fn nth_magic(data: &[u8], idx: usize) -> usize {
        data.windows(3)
            .enumerate()
            .filter(|(_, w)| *w == b"\x1f\x8b\x08")
            .nth(idx)
            .map(|(i, _)| i)
            .unwrap()
    }

    #[test]
    fn auto_salvages_intact_members_around_a_corrupt_one() {
        let mut gz = build::concat_gzip_members(&[b"aaaa\n", b"bbbb\n", b"cccc\n"]);
        let mid = nth_magic(&gz, 1);
        gz[mid + 13] ^= 0xFF; // corrupt member 2 body

        let src = DataSource::from_bytes(Path::new("x.gz"), gz);
        let mut sink = DataSink::new();
        let report = GzMemberSalvage.apply(&src, &mut sink).unwrap();
        assert!(report.success);
        assert!(!sink.is_empty());

        // The spliced output is a valid .gz decoding to the intact members only.
        let mut d = flate2::read::MultiGzDecoder::new(sink.as_bytes());
        let mut out = Vec::new();
        d.read_to_end(&mut out).expect("valid gzip output");
        assert_eq!(out, b"aaaa\ncccc\n");
    }

    #[test]
    fn fully_corrupt_single_member_salvages_nothing() {
        let mut gz = build::gzip_member(b"only member contents here");
        let start = nth_magic(&gz, 0);
        gz[start + 13] ^= 0xFF;
        let src = DataSource::from_bytes(Path::new("x.gz"), gz);
        let mut sink = DataSink::new();
        let report = GzMemberSalvage.apply(&src, &mut sink).unwrap();
        assert!(!report.success);
        assert!(sink.is_empty(), "engine falls through to partial inflate");
    }

    /// End-to-end: the auto-repair engine analyzes a corrupt multi-member gzip,
    /// selects this strategy, and returns the intact members' exact content.
    #[test]
    fn engine_auto_repairs_corrupt_multimember_gzip() {
        use crate::{RecoveryEngine, RecoveryOptions};

        let mut gz = build::concat_gzip_members(&[b"aaaa\n", b"bbbb\n", b"cccc\n"]);
        let mid = nth_magic(&gz, 1);
        gz[mid + 13] ^= 0xFF; // corrupt the middle member

        let (out, report) = RecoveryEngine::new()
            .recover_stream(&gz, Path::new("logs.gz"), &RecoveryOptions::default())
            .expect("recover");

        // The decisive check: output decodes to members 1 & 3 (not just the head).
        let mut d = flate2::read::MultiGzDecoder::new(&out[..]);
        let mut plain = Vec::new();
        d.read_to_end(&mut plain).expect("valid gzip output");
        assert_eq!(plain, b"aaaa\ncccc\n");
        assert!(
            report
                .strategies_applied
                .iter()
                .any(|s| s == "gz-member-salvage"),
            "auto-selected the member salvage: {:?}",
            report.strategies_applied
        );
    }

    /// Full CLI file→file path: analyze a corrupt multi-member `.gz` on disk and
    /// run the engine exactly as `phx recover <file> --output` does.
    #[test]
    fn cli_file_path_auto_repairs_corrupt_multimember_gzip() {
        use std::io::Read as _;

        use phx_analyze_engine::model::AnalysisConfig;
        use phx_analyze_engine::Engine;

        use crate::{RecoveryEngine, RecoveryOptions};

        let mut gz = build::concat_gzip_members(&[b"xxxx\n", b"yyyy\n", b"zzzz\n"]);
        let mid = nth_magic(&gz, 1);
        gz[mid + 13] ^= 0xFF;

        let dir = std::env::temp_dir().join(format!("phx_gzsalv_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("logs.gz");
        std::fs::write(&path, &gz).unwrap();

        let analysis = Engine::new()
            .analyze(&path, AnalysisConfig::default())
            .expect("analyze");
        let out_dir = dir.join("out");
        let options = RecoveryOptions {
            output_dir: out_dir.clone(),
            write_manifest: false,
            ..Default::default()
        };
        let report = RecoveryEngine::new()
            .recover(&path, &analysis, &options)
            .expect("recover");

        let out = std::fs::read(out_dir.join("logs.gz.recovered")).expect("output written");
        let mut plain = Vec::new();
        flate2::read::MultiGzDecoder::new(&out[..])
            .read_to_end(&mut plain)
            .expect("valid gzip");
        assert_eq!(plain, b"xxxx\nzzzz\n");
        assert!(report
            .strategies_applied
            .iter()
            .any(|s| s == "gz-member-salvage"));

        // Source must be untouched (read-only recovery).
        assert_eq!(std::fs::read(&path).unwrap(), gz);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
