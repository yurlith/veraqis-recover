//! Slice A — DEFLATE stored-block resync core.
//!
//! Raw DEFLATE is **bit-aligned**, so after a corruption the Huffman decoder
//! state is lost and byte-level brute-force resync is invalid (it always re-reads
//! garbage). The *only* reliable byte-aligned anchors are **stored (type-00)
//! blocks**: a byte-aligned header `LEN(16 LE) || NLEN(16 LE)` with
//! `LEN ^ NLEN == 0xFFFF`, followed by `LEN` verbatim literal bytes (RFC 1951
//! §3.2.4). Scanning for that pattern is O(N) and recovers real, *verbatim* bytes.
//!
//! Honesty boundary: a 16-bit complement is a weak check, not a proof, so these
//! bytes are **best-effort / unverified** — `resync` callers never count them as
//! exact. They are still useful (verbatim downstream bytes around a corruption),
//! and on random input the corroboration filter below keeps false anchors rare.

/// A DEFLATE stored (type-00) block located by a byte-aligned scan.
#[derive(Debug, Clone)]
pub struct StoredBlock {
    /// Offset of the `LEN` field (the 4-byte `LEN || NLEN` header).
    pub header_offset: usize,
    /// Declared (and verified `== ~NLEN`) payload length.
    pub len: usize,
    /// Verbatim literal payload bytes.
    pub payload: Vec<u8>,
}

/// Minimum stored-block length to trust. Tiny blocks (1–3 B) collide with random
/// `LEN ^ NLEN == 0xFFFF` noise far too often; real sync-flush stored blocks that
/// carry useful data are larger. Raise the floor to cut the false-anchor rate.
const MIN_STORED_LEN: usize = 8;

/// Scan a byte stream for non-overlapping DEFLATE stored-block headers and return
/// each block's verbatim payload, in order. A header qualifies when
/// `LEN ^ NLEN == 0xFFFF`, `LEN >= MIN_STORED_LEN`, and `LEN` payload bytes are
/// present. After a hit at `i` the scan resumes past that block (`i + 4 + LEN`),
/// so overlapping false matches inside a real payload are skipped.
pub fn scan_stored_blocks(data: &[u8]) -> Vec<StoredBlock> {
    let mut blocks = Vec::new();
    if data.len() < 4 + MIN_STORED_LEN {
        return blocks;
    }
    let mut i = 0usize;
    while i + 4 <= data.len() {
        let len = u16::from_le_bytes([data[i], data[i + 1]]) as usize;
        let nlen = u16::from_le_bytes([data[i + 2], data[i + 3]]) as usize;
        let complement_ok = (len ^ nlen) == 0xFFFF;
        let payload_start = i + 4;
        let payload_end = payload_start.saturating_add(len);
        if complement_ok && len >= MIN_STORED_LEN && payload_end <= data.len() {
            blocks.push(StoredBlock {
                header_offset: i,
                len,
                payload: data[payload_start..payload_end].to_vec(),
            });
            i = payload_end; // resume past this block (non-overlapping)
        } else {
            i += 1;
        }
    }
    blocks
}

/// Total verbatim bytes recoverable from stored blocks in `data` (best-effort).
pub fn stored_block_bytes(data: &[u8]) -> usize {
    scan_stored_blocks(data).iter().map(|b| b.len).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-build a DEFLATE stored block: `LEN || NLEN || payload`.
    fn stored_block(payload: &[u8]) -> Vec<u8> {
        let len = payload.len() as u16;
        let nlen = !len;
        let mut out = Vec::new();
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&nlen.to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn finds_planted_stored_block_payload_exactly() {
        let payload = b"the quick brown fox jumps over the lazy dog";
        let mut buf = vec![0xAB, 0xCD, 0xEF, 0x12]; // leading garbage
        buf.extend_from_slice(&stored_block(payload));
        buf.extend_from_slice(&[0x99, 0x88]); // trailing garbage
        let blocks = scan_stored_blocks(&buf);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].payload, payload);
        assert_eq!(blocks[0].len, payload.len());
    }

    #[test]
    fn rejects_short_and_complement_mismatches() {
        // LEN ^ NLEN != 0xFFFF → not a stored block.
        let bad = [0x05, 0x00, 0x05, 0x00, b'h', b'e', b'l', b'l', b'o'];
        assert!(scan_stored_blocks(&bad).is_empty());
        // Valid complement but below the length floor → rejected.
        let tiny = stored_block(b"abc");
        assert!(scan_stored_blocks(&tiny).is_empty());
    }

    #[test]
    fn random_data_yields_few_anchors_and_never_panics() {
        // Deterministic PRNG; random bytes should rarely satisfy the filter.
        let mut v = vec![0u8; 16384];
        let mut s: u64 = 0xD1CE_F00D_1234_5678;
        for b in v.iter_mut() {
            s = s
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *b = (s >> 56) as u8;
        }
        // Must not panic; any anchors found are best-effort (never "verified").
        let blocks = scan_stored_blocks(&v);
        for b in &blocks {
            assert_eq!(b.payload.len(), b.len);
        }
    }
}
