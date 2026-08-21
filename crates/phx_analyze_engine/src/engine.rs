//! The analysis engine: orchestrates the pipeline stages into an
//! [`AnalysisResult`] (or a bare [`IntegrityResult`] for `verify`).
//!
//! The engine writes no stdout (only `tracing`), takes no CLI types, and never
//! imports `phx_recovery` / `phx_protect` — Protection is reached only through
//! the registered hook.

use std::path::Path;
use std::time::Instant;

use tracing::{debug, warn};

use crate::error::EngineError;
use crate::model::{AnalysisConfig, AnalysisResult, ArchiveFormat, IntegrityResult};
use crate::pipeline::{
    corruption_scan, discovery, format_detection, health_assessment, integrity_scan,
    recoverability_scoring, report_assembly,
};
use crate::reader::{reader_for, DataSource, ZipReader};

/// Files larger than this emit a warning but are still processed.
const LARGE_FILE_WARN_BYTES: u64 = 10 * 1024 * 1024 * 1024; // 10 GiB

/// The analysis engine. Holds configuration-independent state only.
#[derive(Debug, Default, Clone)]
pub struct Engine;

impl Engine {
    /// Construct a new engine.
    pub fn new() -> Self {
        Engine
    }

    /// Full analysis of `path`: integrity, corruption, health, recoverability,
    /// and per-file results for archives.
    pub fn analyze(
        &self,
        path: &Path,
        config: AnalysisConfig,
    ) -> Result<AnalysisResult, EngineError> {
        let source = discovery::run(path)?;
        self.analyze_source(source, path, config)
    }

    /// Analyze an already-open [`DataSource`] under a synthetic `label`.
    ///
    /// Identical pipeline to [`Engine::analyze`] but touches no disk for the
    /// target itself — the entry point used by `phx_sandbox`'s recursive walker
    /// to inspect nested containers held in memory (keeping recursive *analyze*
    /// read-only at the OS level). `label` names the node in the result and for
    /// any sidecar lookup; in-memory nodes simply find none.
    pub fn analyze_source(
        &self,
        source: DataSource,
        label: &Path,
        config: AnalysisConfig,
    ) -> Result<AnalysisResult, EngineError> {
        let path = label;
        let start = Instant::now();
        debug!(target: "phx::engine", path = %path.display(), size = source.len(), "analyzing source");

        let mut warnings = Vec::new();
        if source.len() > LARGE_FILE_WARN_BYTES {
            warnings.push(format!(
                "target is {} bytes (> 10 GiB); analysis may be slow",
                source.len()
            ));
        }

        let format = format_detection::detect(&source);
        debug!(target: "phx::engine", format = format.as_str(), "format detected");

        // Encrypted ZIP is detected and flagged, never parsed. Per the spec's
        // test matrix this is a fatal condition (exit code 2), surfaced as an
        // error rather than a partial result.
        if format == ArchiveFormat::Zip {
            ensure_not_encrypted(&source)?;
        }

        let integrity = integrity_scan::run(&source, path, &config)?;

        let scan = corruption_scan::run(&source, format, &integrity, &config);
        if scan.capped {
            warn!(target: "phx::engine", max = config.max_corruptions_reported, "corruption scan hit cap");
            warnings.push(format!(
                "corruption scan stopped after {} findings",
                config.max_corruptions_reported
            ));
        }

        // Combine structural findings with reference-diff findings when a
        // known-good reference is supplied.
        let mut corruptions = scan.corruptions;
        if let Some(reference) = &config.reference {
            match reference_findings(&source, path, reference) {
                Ok(mut found) => corruptions.append(&mut found),
                Err(e) => warnings.push(format!("reference diff skipped: {e}")),
            }
            corruptions = crate::corruption::merge_adjacent(corruptions);
            suppress_truncation_symptoms(&mut corruptions);
        }

        let health_score = health_assessment::run(&corruptions);
        let embedded_checksums_present = embedded_checksums_present(&source, format);
        let recoverability_score = recoverability_scoring::run(
            &source,
            &corruptions,
            format,
            &integrity,
            embedded_checksums_present,
            scan.capped,
            false,
            false,
        );

        let per_file_results = report_assembly::run(&source, format, &corruptions);

        Ok(AnalysisResult {
            target_path: path.to_path_buf(),
            total_size_bytes: source.len(),
            archive_format: Some(format),
            integrity_result: integrity,
            corruptions,
            health_score,
            recoverability_score,
            per_file_results,
            analysis_duration_ms: start.elapsed().as_millis() as u64,
            warnings,
        })
    }

    /// Integrity-only verification of `path`.
    pub fn verify(
        &self,
        path: &Path,
        config: AnalysisConfig,
    ) -> Result<IntegrityResult, EngineError> {
        let source = discovery::run(path)?;
        integrity_scan::run(&source, path, &config)
    }
}

/// Collapse double-counted truncation symptoms. When reference-diff reports a
/// truncation, a structural scan of the same file independently reports the
/// downstream "required structure missing" failures it causes (a tail-truncated
/// ZIP necessarily loses its EOCD; a head-truncated one loses its first local
/// header). Those are the *same physical defect*, so charging health for both
/// double-penalises one truncation. We keep the precise truncation finding and
/// drop the structural symptoms it explains.
fn suppress_truncation_symptoms(corruptions: &mut Vec<crate::model::Corruption>) {
    let truncated = corruptions
        .iter()
        .any(|c| c.chain.primary.rule_id.contains("TRUNC"));
    if !truncated {
        return;
    }
    // Structure-missing rules that a truncation necessarily induces.
    const SYMPTOMS: &[&str] = &[
        "ZIP_EOCD_001",
        "ZIP_EOCD_002",
        "ZIP_EOCD_003",
        "ZIP_CD_001",
        "ZIP_CD_002",
        "ZIP_CD_003",
        "ZIP_LFH_001",
        "TAR_TERM_001",
        "TAR_UST_001",
        "ISO_PVD_001",
    ];
    corruptions.retain(|c| {
        let id = c.chain.primary.rule_id.as_str();
        id.contains("TRUNC") || !SYMPTOMS.contains(&id)
    });
}

/// Read the target and its known-good reference, then run reference-diff
/// detection. The format label is derived from the target's extension.
fn reference_findings(
    source: &DataSource,
    target: &Path,
    reference: &Path,
) -> Result<Vec<crate::model::Corruption>, String> {
    let corrupted = read_all(source).map_err(|e| e.to_string())?;
    let clean = std::fs::read(reference).map_err(|e| e.to_string())?;
    let ext = target
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default();
    let label = crate::corruption::reference::format_label_for_ext(ext);
    Ok(crate::corruption::scan_reference(&corrupted, &clean, label))
}

/// Read an entire data source into memory.
fn read_all(source: &DataSource) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut buf = Vec::with_capacity(source.len() as usize);
    source.stream()?.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Return an [`EngineError::Encrypted`] if any ZIP member is encrypted.
fn ensure_not_encrypted(source: &DataSource) -> Result<(), EngineError> {
    let parse = ZipReader.parse(source);
    if parse.entries.iter().any(|e| e.encrypted) {
        return Err(EngineError::Encrypted(
            "ZIP contains encrypted members".to_string(),
        ));
    }
    Ok(())
}

/// Whether the format carries embedded per-member checksums we can see.
fn embedded_checksums_present(source: &DataSource, format: ArchiveFormat) -> bool {
    if format != ArchiveFormat::Zip {
        return false;
    }
    reader_for(format)
        .entries(source)
        .map(|entries| entries.iter().any(|e| e.stored_crc32.is_some()))
        .unwrap_or(false)
}
