//! Single-pass streaming hasher.
//!
//! Data is read **exactly once**. In the same forward pass we update the
//! global digest and, when `block_size_bytes` is set, the per-block digest.
//! Buffer size is fixed at 64 KiB (`STREAM_BUFFER_BYTES`).

use std::io::Read;

use sha2::Digest;

use crate::error::EngineError;
use crate::model::{BlockVerification, HashType};
use crate::reader::DataSource;

/// Output of one streaming hash pass.
#[derive(Debug, Clone)]
pub struct HashOutcome {
    /// Hex-encoded global digest over all bytes.
    pub actual_hash: String,
    /// Per-block digests, empty unless block hashing was requested.
    ///
    /// At scan time there is no per-block manifest, so `expected` mirrors the
    /// computed value and `matches` is `true` — these records exist so that
    /// Recovery can later diff them against a real reference manifest.
    pub blocks: Vec<BlockVerification>,
}

/// Hash `source` in a single pass with the given algorithm and optional block
/// size. The `max_blocks` cap bounds `BlockVerification` growth per the
/// performance rules (caller passes 500k by default).
pub fn hash_source(
    source: &DataSource,
    hash_type: HashType,
    block_size_bytes: Option<u64>,
    max_blocks: usize,
) -> Result<HashOutcome, EngineError> {
    match hash_type {
        HashType::Sha256 => stream::<sha2::Sha256>(source, block_size_bytes, max_blocks),
        HashType::Sha3_512 => stream::<sha3::Sha3_512>(source, block_size_bytes, max_blocks),
    }
}

/// Generic streaming core. `D` is any `digest::Digest` (SHA-256, SHA3-512).
fn stream<D: Digest>(
    source: &DataSource,
    block_size_bytes: Option<u64>,
    max_blocks: usize,
) -> Result<HashOutcome, EngineError> {
    let mut reader = source
        .stream()
        .map_err(|e| EngineError::io(source.path(), e))?;

    let mut global = D::new();
    let mut blocks = Vec::new();

    let mut block_hasher: Option<D> = block_size_bytes.map(|_| D::new());
    let mut block_filled: u64 = 0;
    let mut block_index: u64 = 0;
    let mut block_offset: u64 = 0;
    let mut blocks_capped = false;

    let mut buf = [0u8; crate::reader::STREAM_BUFFER_BYTES];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| EngineError::io(source.path(), e))?;
        if n == 0 {
            break;
        }
        global.update(&buf[..n]);

        // Feed the block hasher, splitting the chunk on block boundaries.
        if let (Some(size), false) = (block_size_bytes, blocks_capped) {
            let mut pos = 0usize;
            while pos < n {
                let bh = block_hasher.get_or_insert_with(D::new);
                let room = (size - block_filled) as usize;
                let take = room.min(n - pos);
                bh.update(&buf[pos..pos + take]);
                block_filled += take as u64;
                pos += take;

                if block_filled == size {
                    let finished = block_hasher.take().unwrap();
                    let hex = to_hex(&finished.finalize());
                    blocks.push(make_block(block_index, block_offset, size, hex));
                    block_index += 1;
                    block_offset += size;
                    block_filled = 0;
                    if blocks.len() >= max_blocks {
                        blocks_capped = true;
                        break;
                    }
                }
            }
        }
    }

    // Flush a trailing partial block.
    if !blocks_capped {
        if let Some(bh) = block_hasher.take() {
            if block_filled > 0 {
                let hex = to_hex(&bh.finalize());
                blocks.push(make_block(block_index, block_offset, block_filled, hex));
            }
        }
    }

    Ok(HashOutcome {
        actual_hash: to_hex(&global.finalize()),
        blocks,
    })
}

fn make_block(index: u64, offset: u64, length: u64, hex: String) -> BlockVerification {
    BlockVerification {
        block_index: index,
        offset_bytes: offset,
        length_bytes: length,
        expected_hash: hex.clone(),
        actual_hash: hex,
        matches: true,
    }
}

/// Lowercase hex encoding without external dependencies.
pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_of_empty_matches_known_vector() {
        let src = DataSource::from_bytes("empty", Vec::new());
        let out = hash_source(&src, HashType::Sha256, None, 500_000).unwrap();
        assert_eq!(
            out.actual_hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_of_abc_matches_known_vector() {
        let src = DataSource::from_bytes("abc", b"abc".to_vec());
        let out = hash_source(&src, HashType::Sha256, None, 500_000).unwrap();
        assert_eq!(
            out.actual_hash,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn block_hashing_splits_into_expected_count() {
        // 10 bytes, block size 4 → blocks of 4, 4, 2.
        let src = DataSource::from_bytes("d", (0u8..10).collect());
        let out = hash_source(&src, HashType::Sha256, Some(4), 500_000).unwrap();
        assert_eq!(out.blocks.len(), 3);
        assert_eq!(out.blocks[0].length_bytes, 4);
        assert_eq!(out.blocks[2].length_bytes, 2);
        assert_eq!(out.blocks[2].offset_bytes, 8);
    }

    #[test]
    fn sha3_512_digest_is_64_bytes() {
        let src = DataSource::from_bytes("d", b"phx".to_vec());
        let out = hash_source(&src, HashType::Sha3_512, None, 500_000).unwrap();
        assert_eq!(out.actual_hash.len(), 128); // 64 bytes hex
    }
}
