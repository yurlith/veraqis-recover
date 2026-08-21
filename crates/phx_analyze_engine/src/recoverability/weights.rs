//! Recoverability factor weights (Phase 4, Step 4.3).
//!
//! Every factor the estimator can apply is a named constant here with the
//! rationale from the Step 4.2 ground-truth table. The base probability and the
//! class bands are frozen; only these factor weights are tuned during
//! recoverability calibration. The estimator contains no magic numbers — it
//! reads every weight from this module. Calibration history and final values
//! are in `CALIBRATION.md`.

/// Neutral starting probability before any factor is applied.
pub const BASE: f64 = 0.5;

// ── Positive factors ─────────────────────────────────────────────────────────

/// Damage is bit flips only — present but hard to locate without a manifest.
pub const BITFLIP_ONLY: f64 = 0.08;
/// ZIP carries a central directory *and* local headers; one rebuilds the other
/// (`zip -FF` succeeds ~90–95% when the CD is intact).
pub const ZIP_REDUNDANCY: f64 = 0.20;
/// TAR checksum-only damage — `tar --ignore-checksum` reads it almost always.
pub const TAR_CHECKSUM_ONLY: f64 = 0.25;
/// An external manifest precisely locates bit flips.
pub const EXTERNAL_MANIFEST: f64 = 0.18;
/// Per 10% of the stream covered by error-correcting parity (Shield, Phase 8).
pub const ECC_PER_10PCT: f64 = 0.04;
/// Format-embedded checksums (e.g. ZIP CRC-32) are present.
pub const EMBEDDED_CHECKSUMS: f64 = 0.08;
/// Located damage covers < 1% of the stream.
pub const SMALL_DAMAGE_AREA: f64 = 0.12;
/// A linearized PDF survives more damage (the first-page object set is intact).
pub const PDF_LINEARIZATION: f64 = 0.10;
/// SQLite in WAL mode provides transaction-level recovery of the main db.
pub const SQLITE_WAL: f64 = 0.15;

// ── Class floors / ceilings ──────────────────────────────────────────────────

/// Minimum probability for any damage *without* a definitive unrecoverable
/// signal: if a container is damaged at all but its entry signature and header
/// survive, recovery is at worst forensic (Low), never `None`. This keeps the
/// estimator from collapsing merely-hard cases to `None` by stacking negatives.
pub const LOW_FLOOR: f64 = 0.15;
/// Maximum probability once a definitive unrecoverable signal is present
/// (entry signature destroyed, header truncated, page size invalid): forces the
/// `None` band regardless of any offsetting positive factor.
pub const NONE_CEILING: f64 = 0.10;

// ── Negative factors ─────────────────────────────────────────────────────────

/// A format's entry signature/magic is gone (GZIP `\x1F\x8B`, the 7z/RAR/BZ2/
/// XZ/ZSTD/LZ4 signatures, the SQLite/PDF headers). No decoder will even start
/// — a complete blocker. (The Step 4.3 table lists this for GZIP; it applies
/// identically to every format's entry signature.)
pub const SIGNATURE_MISSING: f64 = -0.60;
/// Per region of missing (deleted/zeroed) data.
pub const MISSING_DATA: f64 = -0.28;
/// A catastrophic structural defect with no format redundancy to fall back on.
pub const CATASTROPHIC_STRUCTURAL: f64 = -0.45;
/// Neither a manifest nor embedded checksums to guide recovery.
pub const NO_MANIFEST_NO_CHECKSUMS: f64 = -0.12;
/// Truncation destroyed the header region — near-unrecoverable.
pub const TRUNCATED_AT_HEADER: f64 = -0.45;
/// SQLite page size invalid — no page can be parsed at all.
pub const DB_PAGE_SIZE_INVALID: f64 = -0.55;
