//! Fuzz target: the integrity hasher must never panic on arbitrary input,
//! for either algorithm and any block size.
#![no_main]

use libfuzzer_sys::fuzz_target;
use phx_analyze_engine::integrity::hash_source;
use phx_analyze_engine::model::HashType;
use phx_analyze_engine::reader::DataSource;

fuzz_target!(|data: &[u8]| {
    let src = DataSource::from_bytes("fuzz", data.to_vec());
    // Derive a block size from the input to exercise the block path too.
    let block = if data.is_empty() {
        None
    } else {
        Some((data[0] as u64).max(1))
    };
    let _ = hash_source(&src, HashType::Sha256, block, 500_000);
    let _ = hash_source(&src, HashType::Sha3_512, None, 500_000);
});
