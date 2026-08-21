//! Recovery engine: strategy selection, staged reconstruction, post-recovery
//! verification, and commit-to-output.
//!
//! Invariants enforced here:
//! - Recovery output path is always different from the source path.
//! - Strategies write to an in-memory staging sink; only verified (or
//!   best-effort, when no reference exists) output is committed to disk.
//! - The source is opened read-only and never modified.

use std::path::{Path, PathBuf};

use phx_analyze_engine::integrity::{self, MAX_BLOCKS};
use phx_analyze_engine::model::{AnalysisConfig, AnalysisResult, HashType, IntegrityResult};
use phx_analyze_engine::reader::DataSource;
use phx_analyze_engine::Engine;
use tracing::{debug, info, warn};

use ed25519_dalek::SigningKey;

use crate::manifest::RepairManifest;
use crate::model::{DataSink, RecoveryError, RecoveryReport};
use crate::plan::{RepairPlan, RepairRisk};
use crate::strategies::{all_strategies, read_all, strategy_by_name, RecoveryStrategy};

/// Options controlling a recovery run.
pub struct RecoveryOptions {
    /// Directory into which recovered output is written.
    pub output_dir: PathBuf,
    /// Force a single named strategy instead of auto-selection.
    pub forced_strategy: Option<String>,
    /// Try every applicable strategy even after one succeeds.
    pub aggressive: bool,
    /// Report what would happen without writing any output.
    pub dry_run: bool,
    /// Hash algorithm for post-recovery verification.
    pub hash_type: HashType,
    /// Write a signed repair manifest sidecar (Step 6.3, default on).
    pub write_manifest: bool,
    /// Optional 32-byte Ed25519 seed to sign the manifest with. `None` ⇒ a
    /// per-run ephemeral key (tamper-evidence without authenticated identity).
    pub sign_key: Option<[u8; 32]>,
    /// The calling binary's name, recorded in the manifest's `tool` field
    /// (e.g. `"phx"`, `"veraqis-recover"`) so a manifest correctly identifies
    /// which tool produced it instead of a name hardcoded into this crate.
    pub tool_name: String,
}

impl Default for RecoveryOptions {
    fn default() -> Self {
        RecoveryOptions {
            output_dir: PathBuf::from("."),
            forced_strategy: None,
            aggressive: false,
            dry_run: false,
            hash_type: HashType::Sha256,
            write_manifest: true,
            sign_key: None,
            tool_name: "phx".to_string(),
        }
    }
}

/// Maximum number of repair passes per recovery (Step 6.1). Bounds compound
/// repairs and guarantees termination.
const MAX_PASSES: usize = 3;

/// The best kept output of a recovery run (not yet committed).
#[derive(Default)]
struct PassOutcome {
    /// Recovered bytes, or `None` if no repair was kept.
    bytes: Option<Vec<u8>>,
    /// Plans of the kept strategy, for the manifest.
    kept_plans: Vec<RepairPlan>,
    /// Whether the kept output was byte-verified against a reference.
    output_verified: bool,
}

/// The recovery engine.
#[derive(Debug, Default, Clone)]
pub struct RecoveryEngine;

impl RecoveryEngine {
    pub fn new() -> Self {
        RecoveryEngine
    }

    /// Produce the read-only repair plan for an analysis (Phase 6, Step 6.1).
    ///
    /// Aggregates the rule-keyed [`RepairPlan`]s every applicable strategy would
    /// execute, ordered structural-first (highest strategy priority first). No
    /// bytes are read from the source and nothing is written — this is the data
    /// behind `phx recover --plan`.
    pub fn plan(&self, analysis: &AnalysisResult) -> Vec<RepairPlan> {
        let mut strategies: Vec<Box<dyn RecoveryStrategy>> = all_strategies()
            .into_iter()
            .filter(|s| s.can_apply(analysis))
            .collect();
        strategies.sort_by_key(|s| std::cmp::Reverse(s.priority()));
        strategies.iter().flat_map(|s| s.plan(analysis)).collect()
    }

    /// Run recovery for a previously analyzed `source_path` (file → file).
    pub fn recover(
        &self,
        source_path: &Path,
        analysis: &AnalysisResult,
        options: &RecoveryOptions,
    ) -> Result<RecoveryReport, RecoveryError> {
        let output_path = self.output_path_for(source_path, options);
        if paths_equal(source_path, &output_path) {
            return Err(RecoveryError::OutputEqualsSource);
        }

        let source =
            DataSource::open(source_path).map_err(|e| RecoveryError::io(source_path, e))?;

        let mut aggregate = RecoveryReport::empty(output_path.clone());
        aggregate.health_before = Some(analysis.health_score.overall);

        let outcome =
            match self.run_passes(&source, analysis, options, &output_path, &mut aggregate) {
                Ok(o) => o,
                // Nothing to repair (healthy input or no strategy for the damage):
                // abstain — write no artifact rather than emit a pass-through copy
                // claiming recovered bytes.
                Err(RecoveryError::NoApplicableStrategy) => {
                    aggregate.warnings.push(
                        "no repairable defects detected; nothing to recover (abstain)".to_string(),
                    );
                    PassOutcome::default()
                }
                Err(e) => return Err(e),
            };

        if let Some(bytes) = &outcome.bytes {
            if !options.dry_run {
                self.commit(bytes, &output_path)?;
                // Signed repair manifest (Step 6.3): default-on, records exactly
                // what changed and is Ed25519-signed for tamper-evidence.
                if options.write_manifest {
                    match self.write_manifest(
                        source_path,
                        &source,
                        &output_path,
                        bytes,
                        &outcome.kept_plans,
                        &aggregate,
                        outcome.output_verified,
                        options,
                    ) {
                        Ok(path) => aggregate.manifest_path = Some(path),
                        Err(e) => aggregate
                            .warnings
                            .push(format!("repair manifest not written: {e}")),
                    }
                }
            }
        }

        if options.dry_run {
            aggregate
                .warnings
                .push("dry-run: no output written".to_string());
        } else if outcome.bytes.is_none() {
            aggregate
                .warnings
                .push("no repair improved health; source left unchanged".to_string());
        }

        aggregate.output_path = output_path;
        Ok(aggregate)
    }

    /// Recover an in-memory stream (bytes → bytes), for `--stdin/--stdout`
    /// (Step 6.4). Analyzes the input, runs the same rollback-guarded passes,
    /// and returns the recovered bytes. If no repair applies or improves health,
    /// the input is returned unchanged (a faithful passthrough) with a note. No
    /// manifest sidecar is written for a pure stream.
    pub fn recover_stream(
        &self,
        input: &[u8],
        label: &Path,
        options: &RecoveryOptions,
    ) -> Result<(Vec<u8>, RecoveryReport), RecoveryError> {
        // Use the label (which carries the format extension, e.g. "stream.gz")
        // as the DataSource path so the extension fallback in format_detection
        // fires when magic bytes are corrupted.
        let analysis = Engine::new()
            .analyze_source(
                DataSource::from_bytes(label, input.to_vec()),
                label,
                AnalysisConfig::default(),
            )
            .map_err(|e| RecoveryError::Strategy {
                strategy: "analyze".to_string(),
                reason: e.to_string(),
            })?;

        let mut aggregate = RecoveryReport::empty(PathBuf::from("-"));
        aggregate.health_before = Some(analysis.health_score.overall);

        let source = DataSource::from_bytes(label, input.to_vec());
        let outcome = match self.run_passes(&source, &analysis, options, label, &mut aggregate) {
            Ok(o) => o,
            // No applicable strategy ⇒ pass the stream through unchanged.
            Err(RecoveryError::NoApplicableStrategy) => PassOutcome::default(),
            Err(e) => return Err(e),
        };

        let bytes = outcome.bytes.unwrap_or_else(|| {
            aggregate
                .warnings
                .push("no repair applied; stream passed through unchanged".to_string());
            input.to_vec()
        });
        aggregate.output_path = PathBuf::from("-");
        Ok((bytes, aggregate))
    }

    /// Run the bounded, rollback-guarded repair passes against an open source,
    /// returning the best kept output **without committing it**. Shared by
    /// [`recover`](Self::recover) and [`recover_stream`](Self::recover_stream).
    fn run_passes(
        &self,
        source: &DataSource,
        analysis: &AnalysisResult,
        options: &RecoveryOptions,
        label: &Path,
        aggregate: &mut RecoveryReport,
    ) -> Result<PassOutcome, RecoveryError> {
        let selected = self.select(analysis, options)?;
        debug!(target: "phx::recovery", count = selected.len(), "selected recovery strategies");

        let base_health = analysis.health_score.overall;
        let mut outcome = PassOutcome::default();

        // Bounded passes (Step 6.1: max 3), structural-first by selection order.
        for strategy in selected.iter().take(MAX_PASSES) {
            let mut sink = DataSink::new();
            let mut report = strategy.apply(source, &mut sink)?;
            report.output_path = label.to_path_buf();
            report.health_before = Some(base_health);

            // Post-recovery verification against the source's reference hash.
            let integ = self.verify(&sink, analysis, options.hash_type)?;
            let verified = integ.matches;
            report.post_recovery_integrity = Some(integ);

            // Full re-analysis of the staged output (Step 6.1 rollback gate).
            let after = self.reanalyze_health(&sink, label);
            report.health_after = after;

            let regressed = matches!(after, Some(h) if h < base_health);
            let improved = matches!(after, Some(h) if h > base_health);
            let held = matches!(after, Some(h) if h == base_health);
            let terminal = report_is_terminal(strategy.as_ref());

            // Auto-rollback: never keep output that regresses health. Keep a
            // repair that is byte-verified, that improves health, or that is a
            // faithful salvage holding health steady.
            //
            // Inferred-risk repairs are held to the strict bar: byte-verified
            // only. An inferred repair asserts an unproven hypothesis (e.g. a
            // trailer recomputed to fit the data), so the health gain measured
            // on its own output is manufactured by the rewrite — a fitted
            // verifier contributes zero evidence bits (Evidence model,
            // tautology rule) and must not justify keeping the result.
            let inferred = matches!(strategy.risk(), RepairRisk::Inferred);
            let keep = !sink.is_empty()
                && !regressed
                && if inferred {
                    verified
                } else {
                    verified || improved || (held && terminal)
                };

            if !keep {
                let reason = if sink.is_empty() {
                    "staged no output (nothing salvageable)".to_string()
                } else if inferred {
                    "inferred repair not byte-verified (a fitted verifier cannot justify keeping)"
                        .to_string()
                } else {
                    format!(
                        "health {} -> {} (no improvement)",
                        base_health,
                        after.map(|h| h.to_string()).unwrap_or_else(|| "?".into())
                    )
                };
                warn!(
                    target: "phx::recovery",
                    strategy = strategy.name(),
                    before = base_health,
                    after = ?after,
                    reason = %reason,
                    "rolled back"
                );
                aggregate.rolled_back.push(strategy.name().to_string());
                aggregate
                    .warnings
                    .push(format!("rolled back {}: {}", strategy.name(), reason));
                continue;
            }

            report.success = verified || improved || terminal;
            aggregate.merge(report);
            // Record the (latest) kept output's provenance.
            outcome.bytes = Some(sink.as_bytes().to_vec());
            outcome.kept_plans = strategy.plan(analysis);
            outcome.output_verified = verified;

            // Stop once we have a verified or health-improving result, unless
            // the caller asked to try everything.
            if (verified || improved) && !options.aggressive {
                break;
            }
        }
        Ok(outcome)
    }

    /// Build, sign, and write the repair manifest sidecar. Returns its path.
    #[allow(clippy::too_many_arguments)]
    fn write_manifest(
        &self,
        source_path: &Path,
        source: &DataSource,
        output_path: &Path,
        output_bytes: &[u8],
        plans: &[RepairPlan],
        aggregate: &RecoveryReport,
        output_verified: bool,
        options: &RecoveryOptions,
    ) -> Result<PathBuf, RecoveryError> {
        let source_bytes = read_all(source)?;
        let key = match options.sign_key {
            Some(seed) => SigningKey::from_bytes(&seed),
            None => SigningKey::generate(&mut rand::rngs::OsRng),
        };
        let entries = entry_evidence_records(&source_bytes, output_bytes, plans);
        let manifest = RepairManifest::build(
            &source_path.display().to_string(),
            &output_path.display().to_string(),
            &source_bytes,
            output_bytes,
            plans,
            entries,
            aggregate.bytes_recovered,
            aggregate.bytes_lost,
            output_verified,
            &key,
            &options.tool_name,
        );
        let mut os = output_path.as_os_str().to_owned();
        os.push(".phxr.json");
        let path = PathBuf::from(os);
        std::fs::write(&path, manifest.to_json()).map_err(|e| RecoveryError::io(&path, e))?;
        info!(target: "phx::recovery", path = %path.display(), "wrote signed repair manifest");
        Ok(path)
    }

    /// Re-analyze staged bytes in memory and return the overall health score.
    /// Returns `None` if re-analysis fails (treated conservatively by the
    /// caller — only byte-verified output is kept when health is unknown).
    fn reanalyze_health(&self, sink: &DataSink, label: &Path) -> Option<u8> {
        let src = DataSource::from_bytes("recovered", sink.as_bytes().to_vec());
        Engine::new()
            .analyze_source(src, label, AnalysisConfig::default())
            .ok()
            .map(|a| a.health_score.overall)
    }

    /// Choose strategies: forced name, or all applicable sorted by priority.
    fn select(
        &self,
        analysis: &AnalysisResult,
        options: &RecoveryOptions,
    ) -> Result<Vec<Box<dyn RecoveryStrategy>>, RecoveryError> {
        if let Some(name) = &options.forced_strategy {
            let s = strategy_by_name(name).ok_or_else(|| RecoveryError::Strategy {
                strategy: name.clone(),
                reason: "unknown strategy name".to_string(),
            })?;
            return Ok(vec![s]);
        }

        // Tier-0 gate: no detected defects ⇒ nothing provable to repair ⇒
        // abstain. Without this, format-scoped strategies (e.g. extraction
        // salvage) fire on inputs that analyze scored healthy and emit a
        // "recovered" artifact for a file that needed no recovery — which also
        // silently launders damage the format cannot evidence (tar carries no
        // payload checksums; EXP-PCRB-PUBLIC run 1 measured corrupt data bytes
        // passed through inside an artifact claiming `recovered=216576B`).
        if analysis.corruptions.is_empty() {
            return Err(RecoveryError::NoApplicableStrategy);
        }

        let mut applicable: Vec<Box<dyn RecoveryStrategy>> = all_strategies()
            .into_iter()
            .filter(|s| s.can_apply(analysis))
            .collect();
        applicable.sort_by_key(|s| std::cmp::Reverse(s.priority()));

        if applicable.is_empty() {
            return Err(RecoveryError::NoApplicableStrategy);
        }
        Ok(applicable)
    }

    /// Verify staged bytes against the source's reference hash (if any).
    fn verify(
        &self,
        sink: &DataSink,
        analysis: &AnalysisResult,
        hash_type: HashType,
    ) -> Result<IntegrityResult, RecoveryError> {
        let staged = DataSource::from_bytes("recovered", sink.as_bytes().to_vec());
        let outcome =
            integrity::hash_source(&staged, hash_type, None, MAX_BLOCKS).map_err(|e| {
                RecoveryError::Strategy {
                    strategy: "verification".to_string(),
                    reason: e.to_string(),
                }
            })?;

        let mut result = IntegrityResult::without_manifest(hash_type, outcome.actual_hash);
        if let Some(expected) = &analysis.integrity_result.expected_hash {
            result.manifest_present = analysis.integrity_result.manifest_present;
            result.matches = *expected == result.actual_hash;
            result.expected_hash = Some(expected.clone());
        }
        Ok(result)
    }

    /// Write the recovered bytes to the output path.
    fn commit(&self, bytes: &[u8], output_path: &Path) -> Result<(), RecoveryError> {
        if let Some(parent) = output_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| RecoveryError::io(parent, e))?;
            }
        }
        std::fs::write(output_path, bytes).map_err(|e| RecoveryError::io(output_path, e))?;
        info!(target: "phx::recovery", path = %output_path.display(), bytes = bytes.len(), "committed recovered output");
        Ok(())
    }

    /// Default output path: `<output_dir>/<stem>.recovered<.ext>`.
    fn output_path_for(&self, source_path: &Path, options: &RecoveryOptions) -> PathBuf {
        let file_name = source_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "output".to_string());
        options.output_dir.join(format!("{file_name}.recovered"))
    }
}

/// Whether a strategy's output is worth committing even without verification
/// (the readable-bytes strategies that never fabricate data).
fn report_is_terminal(strategy: &dyn RecoveryStrategy) -> bool {
    matches!(
        strategy.name(),
        "partial-extract"
            | "forensic-carve"
            | "zip-rebuild"
            | "gz-member-salvage"
            | "tar-continuation-salvage"
    )
}

fn paths_equal(a: &Path, b: &Path) -> bool {
    // Compare canonicalized paths when possible; fall back to literal equality.
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(ca), Ok(cb)) => ca == cb,
        _ => a == b,
    }
}

/// Classify every entry of a recovered ZIP against the evidence the *source* actually offered.
///
/// The manifest is what a downstream consumer believes, so it has to carry the justification for
/// each entry rather than a single aggregate byte count. Two properties are kept apart on purpose:
///
/// * **existence** — did this entry belong to this archive? Only a complete, independent central
///   directory attests that. A local-header scan finds headers; it cannot tell a genuine one from
///   a planted one, because both are self-describing.
/// * **content** — are these the original bytes? A CRC-32 answers that, but only as strongly as
///   the header carrying it is trustworthy. When the header is all the evidence there is, the
///   checksum is self-consistent rather than independent, and the record says so.
///
/// A directory PHX rebuilt from the very local headers it would attest is not an independent
/// witness (DEC-016 §5). It is labelled `RECONSTRUCTED`, never `ORIGINAL_SURVIVING` — otherwise a
/// repair would manufacture the evidence that launders a planted entry into a recovered one.
fn entry_evidence_records(
    source_bytes: &[u8],
    output_bytes: &[u8],
    plans: &[RepairPlan],
) -> Vec<crate::manifest::EntryEvidenceRecord> {
    use crate::manifest::EntryEvidenceRecord;
    // `semantic::opc::zip` is itself only a re-export of `phx_zip_core::opc_zip`
    // — go straight to the real, open source instead of routing through the
    // closed `semantic` module (OPEN_CORE_STRATEGY.md §4).
    use phx_zip_core::opc_zip::{extract_entry, parse_zip, ExtractStatus};

    let src = parse_zip(source_bytes);
    // Names the SOURCE's directory attested, and only when that directory was complete enough for
    // its silence to mean anything (see `cd_count_consistent`).
    let attested: std::collections::HashSet<&str> = if src.cd_count_consistent {
        src.entries
            .iter()
            .filter(|e| e.from_central_dir)
            .map(|e| e.name.as_str())
            .collect()
    } else {
        std::collections::HashSet::new()
    };

    let cd_rebuilt = plans
        .iter()
        .any(|p| matches!(p.technique, "CentralDirRebuild" | "EocdReconstruct"));
    let cd_provenance = if cd_rebuilt {
        "RECONSTRUCTED"
    } else if src.cd_found && !src.cd_recovered_by_scan {
        "ORIGINAL_SURVIVING"
    } else if src.cd_found {
        "RECONSTRUCTED"
    } else {
        "ABSENT"
    };

    let out = parse_zip(output_bytes);
    out.entries
        .iter()
        .map(|e| {
            let extracted = extract_entry(output_bytes, e);
            let crc_ok = extracted.status == ExtractStatus::VerifiedCrc;
            let exists = attested.contains(e.name.as_str());

            let (verdict, trusted, abstention) = match (exists, crc_ok) {
                (true, true) => ("EXACT_RECOVERABLE", true, None),
                (true, false) => (
                    "SALVAGED_UNVERIFIED",
                    false,
                    Some("content checksum did not verify".to_string()),
                ),
                (false, _) => (
                    "SALVAGED_UNVERIFIED",
                    false,
                    Some(
                        "no complete independent central directory attests that this entry \
                         belonged to the archive; its checksum proves only that the payload \
                         matches its own header"
                            .to_string(),
                    ),
                ),
            };

            EntryEvidenceRecord {
                path: e.name.clone(),
                verdict: verdict.to_string(),
                existence_evidence: if exists {
                    "COMPLETE_CENTRAL_DIRECTORY".to_string()
                } else {
                    "LOCAL_HEADER_SCAN_ONLY".to_string()
                },
                content_evidence: match (crc_ok, exists) {
                    (true, true) => "CRC32_INDEPENDENT".to_string(),
                    (true, false) => "CRC32_SELF_CONSISTENT_ONLY".to_string(),
                    (false, _) => "NONE".to_string(),
                },
                evidence_provenance: if cd_rebuilt {
                    "PHX_RECONSTRUCTED".to_string()
                } else {
                    "ARCHIVE_AS_FOUND".to_string()
                },
                central_directory_provenance: cd_provenance.to_string(),
                trusted_metric_inclusion: trusted,
                abstention_reason: abstention,
            }
        })
        .collect()
}
