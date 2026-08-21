//! Stage 3 — Integrity scan. Wraps [`crate::integrity`] and, when a Protection
//! hook is registered, attaches a signature-verification result. The hook is
//! the *only* path from Analysis to Protection.

use std::path::Path;

use crate::error::EngineError;
use crate::integrity;
use crate::model::{AnalysisConfig, IntegrityResult, SignatureVerificationResult};
use crate::reader::DataSource;

/// Run integrity verification for `source`, comparing against a sidecar
/// manifest of `target` if present, then optionally verifying a signature.
pub fn run(
    source: &DataSource,
    target: &Path,
    config: &AnalysisConfig,
) -> Result<IntegrityResult, EngineError> {
    let lookup_name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    let mut result = integrity::run_with_manifest(
        source,
        target,
        &lookup_name,
        config.hash_type,
        config.block_size_bytes,
    )?;

    if let Some(hook) = &config.protection_hook {
        result.signature_verification = Some(verify_signature(source, hook.as_ref())?);
    }

    Ok(result)
}

/// Read the whole source and ask the Protection hook to verify its signature.
fn verify_signature(
    source: &DataSource,
    hook: &dyn crate::hooks::ProtectionHook,
) -> Result<SignatureVerificationResult, EngineError> {
    let data = read_all(source)?;
    let valid = hook.verify_signature(&data)?;
    Ok(SignatureVerificationResult {
        valid,
        key_id: hook.key_id(),
        algorithm: hook.signature_algorithm().to_string(),
    })
}

/// Read the entire source into memory (signature verification needs all bytes).
fn read_all(source: &DataSource) -> Result<Vec<u8>, EngineError> {
    use std::io::Read;
    let mut buf = Vec::with_capacity(source.len() as usize);
    source
        .stream()
        .map_err(|e| EngineError::io(source.path(), e))?
        .read_to_end(&mut buf)
        .map_err(|e| EngineError::io(source.path(), e))?;
    Ok(buf)
}
