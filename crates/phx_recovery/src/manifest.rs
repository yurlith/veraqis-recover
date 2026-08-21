//! Signed repair manifest (Phase 6, Step 6.3).
//!
//! Every recovery emits an auditable record of exactly what was changed: per
//! repair the rule, technique, byte range and provenance guarantee; the
//! before/after SHA-256 of the whole file; and the verified/unverified/lost
//! byte triad. The manifest is Ed25519-signed so any later edit is detectable.
//!
//! Signing key: a caller-supplied key authenticates the manifest to a trusted
//! identity (Phase 9 org keys). With no key, a per-run ephemeral key is used and
//! its public key embedded — that detects accidental corruption/truncation of
//! the manifest, though authenticity needs a trusted key.

use ed25519_dalek::{Signer, SigningKey};
use phx_analyze_engine::model::ByteRange;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::plan::{RepairPlan, RepairRisk};

/// Manifest schema version.
pub const MANIFEST_VERSION: &str = "phxr-1.0";

/// Provenance guarantee for a repair (the verified / unverified / lost triad).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Guarantee {
    /// Byte-exact: confirmed against a reference hash, or copied verbatim from
    /// intact source data.
    Verified,
    /// Reconstructed without a reference to confirm — present but unproven.
    Unverified,
    /// Could not be recovered; the data was dropped.
    Lost,
}

impl Guarantee {
    /// Map a planned repair's risk to its headline guarantee, given whether the
    /// whole output was byte-verified against a reference.
    fn from_risk(risk: RepairRisk, output_verified: bool) -> Self {
        match risk {
            RepairRisk::Safe if output_verified => Guarantee::Verified,
            RepairRisk::Safe | RepairRisk::Inferred => Guarantee::Unverified,
            RepairRisk::Lossy => Guarantee::Lost,
        }
    }
}

/// Aggregate byte counts for the guarantees triad.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
pub struct GuaranteeTriad {
    pub verified_bytes: u64,
    pub unverified_bytes: u64,
    pub lost_bytes: u64,
}

/// One repair's record.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RepairRecord {
    pub rule_id: String,
    pub technique: String,
    pub target_range: Option<ByteRange>,
    pub risk: String,
    pub guarantee: Guarantee,
}

impl RepairRecord {
    fn from_plan(p: &RepairPlan, output_verified: bool) -> Self {
        RepairRecord {
            rule_id: p.rule_id.clone(),
            technique: p.technique.to_string(),
            target_range: p.target_range,
            risk: p.risk.label().to_string(),
            guarantee: Guarantee::from_risk(p.risk, output_verified),
        }
    }
}

/// The signable body of the manifest — everything the signature covers. Kept as
/// a separate struct so signing and verification serialize *exactly* the same
/// bytes, independent of the signature/key fields.
#[derive(Debug, Clone, Serialize)]
pub struct ManifestBody {
    pub format_version: String,
    pub tool: String,
    pub source_path: String,
    pub output_path: String,
    pub source_sha256: String,
    pub output_sha256: String,
    pub repairs: Vec<RepairRecord>,
    /// Per-entry evidence provenance for everything the recovery emitted.
    ///
    /// A phantom kept off disk can still be classified as trusted in the machine-readable output,
    /// and those are different properties: the manifest is what a downstream consumer believes.
    /// Without this section a caller can see *that* bytes were recovered but not *what justified*
    /// any individual entry, so nothing stops a scan-only candidate being read as a verified one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<EntryEvidenceRecord>,
    pub guarantees: GuaranteeTriad,
}

/// What justified one emitted entry — the fields a consumer needs to decide whether to believe it.
///
/// Deliberately splits *existence* from *content*. A CRC-32 proves the payload matches the header
/// that describes it; it says nothing about whether that header ever belonged to this archive.
/// Collapsing the two is the phantom-entry defect in one field.
#[derive(Debug, Clone, Serialize)]
pub struct EntryEvidenceRecord {
    pub path: String,
    /// `EXACT_RECOVERABLE` | `RECOVERABLE_WITH_METADATA_LOSS` | `SALVAGED_UNVERIFIED` |
    /// `REJECTED_PHANTOM` | `UNRECOVERABLE` | `UNKNOWN`.
    pub verdict: String,
    /// What attests the entry EXISTED in this archive — e.g. `COMPLETE_CENTRAL_DIRECTORY`,
    /// `LOCAL_HEADER_SCAN_ONLY`, `NONE`.
    pub existence_evidence: String,
    /// What attests the BYTES are the original bytes — e.g. `CRC32_INDEPENDENT`,
    /// `CRC32_SELF_CONSISTENT_ONLY`, `NONE`.
    pub content_evidence: String,
    /// Where that evidence came from — `ARCHIVE_AS_FOUND` or `PHX_RECONSTRUCTED`.
    pub evidence_provenance: String,
    /// `ORIGINAL_SURVIVING` | `RECONSTRUCTED` | `ABSENT`. A directory PHX rebuilt from the very
    /// local headers it would attest is not an independent witness, and must never be labelled
    /// surviving-original.
    pub central_directory_provenance: String,
    /// Whether this entry counts toward trusted recovery metrics.
    pub trusted_metric_inclusion: bool,
    /// Why it was not trusted, when it was not. `null` when the entry is trusted.
    pub abstention_reason: Option<String>,
}

impl ManifestBody {
    /// Canonical bytes that get signed (stable serde_json serialization).
    fn signing_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("manifest body serializes")
    }
}

/// The full signed manifest written to disk.
#[derive(Debug, Clone, Serialize)]
pub struct RepairManifest {
    #[serde(flatten)]
    pub body: ManifestBody,
    /// SHA-256 fingerprint (16 hex chars) of the signing public key.
    pub key_id: String,
    /// Signing public key, hex (32 bytes).
    pub public_key: String,
    /// Ed25519 signature over [`ManifestBody::signing_bytes`], hex (64 bytes).
    pub signature: String,
}

impl RepairManifest {
    /// Build and sign a manifest. `repairs` are the plans that were actually
    /// kept; `output_verified` is whether the output matched a reference hash.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        source_path: &str,
        output_path: &str,
        source_bytes: &[u8],
        output_bytes: &[u8],
        repairs: &[RepairPlan],
        entries: Vec<EntryEvidenceRecord>,
        bytes_recovered: u64,
        bytes_lost: u64,
        output_verified: bool,
        key: &SigningKey,
        tool_name: &str,
    ) -> Self {
        let records = repairs
            .iter()
            .map(|p| RepairRecord::from_plan(p, output_verified))
            .collect();

        // Triad: with a reference match the recovered bytes are Verified;
        // otherwise they are reconstructed-but-unproven (Unverified). Dropped
        // bytes are always Lost.
        let triad = if output_verified {
            GuaranteeTriad {
                verified_bytes: bytes_recovered,
                unverified_bytes: 0,
                lost_bytes: bytes_lost,
            }
        } else {
            GuaranteeTriad {
                verified_bytes: 0,
                unverified_bytes: bytes_recovered,
                lost_bytes: bytes_lost,
            }
        };

        let body = ManifestBody {
            format_version: MANIFEST_VERSION.to_string(),
            tool: format!("{tool_name} {}", env!("CARGO_PKG_VERSION")),
            source_path: source_path.to_string(),
            output_path: output_path.to_string(),
            source_sha256: hex(&Sha256::digest(source_bytes)),
            output_sha256: hex(&Sha256::digest(output_bytes)),
            repairs: records,
            entries,
            guarantees: triad,
        };

        let vk = key.verifying_key();
        let signature = key.sign(&body.signing_bytes()).to_bytes();
        RepairManifest {
            key_id: key_id(&vk.to_bytes()),
            public_key: hex(&vk.to_bytes()),
            signature: hex(&signature),
            body,
        }
    }

    /// Pretty JSON for the sidecar file.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("manifest serializes")
    }

    /// Verify the signature against the embedded public key. Detects any edit to
    /// the manifest body after signing. Returns `false` on any malformed field.
    pub fn verify(&self) -> bool {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let (Some(pk), Some(sig)) = (
            unhex(&self.public_key).and_then(|b| <[u8; 32]>::try_from(b).ok()),
            unhex(&self.signature).and_then(|b| <[u8; 64]>::try_from(b).ok()),
        ) else {
            return false;
        };
        let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
            return false;
        };
        vk.verify(&self.body.signing_bytes(), &Signature::from_bytes(&sig))
            .is_ok()
    }
}

/// SHA-256 fingerprint (first 16 hex chars) of a public key.
fn key_id(public_key: &[u8]) -> String {
    hex(&Sha256::digest(public_key))[..16].to_string()
}

fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 0x0f) as usize] as char);
    }
    s
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> RepairPlan {
        RepairPlan::new(
            "ZIP_EOCD_001",
            "CentralDirRebuild",
            Some(ByteRange::new(0, 4)),
            "rebuild",
            RepairRisk::Safe,
        )
    }

    #[test]
    fn signed_manifest_verifies() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let m = RepairManifest::build(
            "in.zip",
            "out.zip",
            b"source",
            b"output",
            &[plan()],
            Vec::new(),
            100,
            0,
            false,
            &key,
            "test-tool",
        );
        assert!(m.verify(), "freshly signed manifest must verify");
        assert_eq!(m.body.guarantees.unverified_bytes, 100);
        assert_eq!(m.body.repairs[0].guarantee, Guarantee::Unverified);
        assert!(
            m.body.tool.starts_with("test-tool "),
            "tool name must be the caller's, not hardcoded"
        );
    }

    #[test]
    fn tampering_breaks_verification() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut m = RepairManifest::build(
            "in.zip",
            "out.zip",
            b"source",
            b"output",
            &[plan()],
            Vec::new(),
            100,
            0,
            true,
            &key,
            "test-tool",
        );
        // Verified output ⇒ Verified guarantee.
        assert_eq!(m.body.repairs[0].guarantee, Guarantee::Verified);
        assert!(m.verify());
        // Alter the recorded output hash after signing.
        m.body.output_sha256 = hex(&Sha256::digest(b"different"));
        assert!(!m.verify(), "edited manifest must fail verification");
    }

    #[test]
    fn hex_roundtrips() {
        let bytes = [0x00, 0x1f, 0xa5, 0xff];
        assert_eq!(unhex(&hex(&bytes)).unwrap(), bytes);
        assert!(unhex("xyz").is_none());
    }
}
