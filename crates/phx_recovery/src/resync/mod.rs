//! Exact-recovery bounded resync + member/continuation salvage (roadmap weeks 3–4).
//!
//! GZIP/DEFLATE/TAR quick wins at the **Exact tier**: return real downstream bytes
//! that survive a corruption — and prove them by checksum wherever the format
//! provides one. The binding rule here is the same as everywhere else in PHX:
//!
//! > **A byte is only counted *verified* when surviving bytes prove it.**
//!
//! - **GZIP** is a concatenation of members, each ending in a CRC32 + ISIZE
//!   trailer. A member that inflates *and* matches its trailer is **exact** —
//!   recovering the intact members around a corrupt one is a true exact win.
//! - **TAR** is 512-byte blocks; each member header carries a ustar checksum. A
//!   header that validates with its full data range present yields **exact** bytes
//!   (header-proven, exactly as `tar -x --ignore-zeros` trusts it). TAR has no
//!   per-file *data* CRC — that limit is documented, not hidden.
//! - **DEFLATE** is bit-aligned: byte-level brute-force resync is invalid. The only
//!   reliable byte-aligned anchors are **stored (type-00) blocks** (`LEN ^ NLEN ==
//!   0xFFFF`). Their payload is verbatim, but a 16-bit complement is not proof, so
//!   stored-block salvage is **best-effort / unverified** and never counts toward
//!   the exact gate.
//!
//! Gate (Exact layer): `false_recovered_bytes = 0` over verified segments; a random
//! negative control yields zero verified bytes. See `phx-gzip-tar-resync-bench`.

pub mod build;
pub mod deflate;
pub mod gzip;
pub mod tar;

pub use deflate::{scan_stored_blocks, StoredBlock};
pub use gzip::salvage_gzip;
pub use tar::salvage_tar;

/// How a salvaged segment was (or was not) proven.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentKind {
    /// A whole GZIP member that inflated and whose CRC32 + ISIZE trailer matched —
    /// exact, checksum-proven bytes.
    VerifiedGzipMember,
    /// A whole TAR member whose ustar header checksum validated and whose data
    /// range is fully present — exact, header-proven bytes (as `tar -x`).
    VerifiedTarMember,
    /// Verbatim bytes from a DEFLATE stored (type-00) block (`LEN ^ NLEN ==
    /// 0xFFFF`) — recovered but not independently proven (best-effort).
    StoredBlockSalvage,
    /// Leading bytes inflated from a corrupt member before the error — lossy,
    /// unverified.
    PartialInflate,
}

impl SegmentKind {
    /// Exact, checksum/structure-proven bytes — the only kind counted as verified.
    pub fn is_verified(self) -> bool {
        matches!(
            self,
            SegmentKind::VerifiedGzipMember | SegmentKind::VerifiedTarMember
        )
    }
}

/// One recovered run of bytes plus the proof (or lack of it) behind it.
#[derive(Debug, Clone)]
pub struct Segment {
    pub kind: SegmentKind,
    /// TAR member path, or a gzip member label (`member#N`).
    pub name: Option<String>,
    /// Byte offset in the source where this segment originated.
    pub source_offset: usize,
    /// End offset (exclusive) of this segment's bytes **in the source** — for a
    /// verified member this is the whole on-disk member span (header + body +
    /// trailer / padding), so callers can splice the original bytes back into a
    /// repaired archive byte-for-byte. Clamped to the source length.
    pub source_end: usize,
    /// Recovered plaintext / data bytes (verbatim for verified segments).
    pub bytes: Vec<u8>,
    pub note: String,
}

impl Segment {
    pub fn verified(&self) -> bool {
        self.kind.is_verified()
    }
}

/// The outcome of salvaging one container.
#[derive(Debug, Clone, Default)]
pub struct SalvageResult {
    pub format: &'static str,
    pub segments: Vec<Segment>,
    /// Members / structures detected (verified or not).
    pub members_total: usize,
    /// Members emitted as exact (checksum/structure-proven).
    pub members_verified: usize,
    /// Exact, proven bytes.
    pub verified_bytes: u64,
    /// Best-effort salvage bytes (never proven — informational).
    pub unverified_bytes: u64,
    pub warnings: Vec<String>,
}

impl SalvageResult {
    pub fn new(format: &'static str) -> Self {
        SalvageResult {
            format,
            ..Default::default()
        }
    }

    /// Record a segment, updating byte/member tallies.
    pub fn push(&mut self, seg: Segment) {
        if seg.verified() {
            self.verified_bytes += seg.bytes.len() as u64;
            self.members_verified += 1;
        } else {
            self.unverified_bytes += seg.bytes.len() as u64;
        }
        self.segments.push(seg);
    }

    /// Concatenated exact bytes (verified segments only) — safe to return.
    pub fn verified_payload(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for s in &self.segments {
            if s.verified() {
                out.extend_from_slice(&s.bytes);
            }
        }
        out
    }
}
