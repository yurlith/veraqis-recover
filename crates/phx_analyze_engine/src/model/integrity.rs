//! Integrity-related model types (Module 3 output shapes).
//!
//! These types are *data only* — no hashing logic lives here. The actual
//! single-pass streaming hashers live in [`crate::integrity`].

use serde::{Deserialize, Serialize};

/// Hash algorithm used for integrity verification.
///
/// PHX deliberately excludes MD5, SHA-1 and Keccak. `Sha3_512` is NIST
/// FIPS 202 SHA3-512, **not** Keccak-512.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum HashType {
    /// SHA-256 (32-byte digest). Default.
    #[default]
    Sha256,
    /// SHA3-512 (64-byte digest, FIPS 202). High-security / post-quantum.
    Sha3_512,
}

impl HashType {
    /// Digest length in bytes.
    pub fn digest_len(self) -> usize {
        match self {
            HashType::Sha256 => 32,
            HashType::Sha3_512 => 64,
        }
    }

    /// File extension of the matching coreutils-style manifest.
    pub fn manifest_extension(self) -> &'static str {
        match self {
            HashType::Sha256 => "sha256",
            HashType::Sha3_512 => "sha3_512",
        }
    }

    /// Human-readable algorithm name.
    pub fn name(self) -> &'static str {
        match self {
            HashType::Sha256 => "SHA-256",
            HashType::Sha3_512 => "SHA3-512",
        }
    }
}

/// Per-block verification record.
///
/// Emitted only when `AnalysisConfig::block_size_bytes` is set. Block hashes
/// share the configured [`HashType`] with the global hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockVerification {
    pub block_index: u64,
    pub offset_bytes: u64,
    pub length_bytes: u64,
    pub expected_hash: String,
    pub actual_hash: String,
    pub matches: bool,
}

/// Result of a digital-signature verification, injected by the Protection
/// hook (Module 6). The engine never produces this itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureVerificationResult {
    pub valid: bool,
    /// Key fingerprint only — never raw key material.
    pub key_id: Option<String>,
    pub algorithm: String,
}

/// Outcome of integrity verification for a single data stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityResult {
    pub hash_type: HashType,
    /// Reference hash from a manifest, if one was found.
    pub expected_hash: Option<String>,
    /// Hash actually computed over the data.
    pub actual_hash: String,
    /// `true` iff a reference hash was present and matched.
    pub matches: bool,
    pub manifest_present: bool,
    pub verified_blocks: Vec<BlockVerification>,
    /// Set only when a Protection hook verified a signature.
    pub signature_verification: Option<SignatureVerificationResult>,
}

impl IntegrityResult {
    /// Construct a result for data with no reference hash available.
    ///
    /// `matches` is `false` because there is nothing to match against;
    /// callers must treat "no manifest" as *unknown*, not *corrupt*.
    pub fn without_manifest(hash_type: HashType, actual_hash: String) -> Self {
        IntegrityResult {
            hash_type,
            expected_hash: None,
            actual_hash,
            matches: false,
            manifest_present: false,
            verified_blocks: Vec::new(),
            signature_verification: None,
        }
    }
}
