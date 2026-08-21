//! Fuzz target: format detection + corruption scan must never panic on
//! arbitrary input, across every format reader.
#![no_main]

use libfuzzer_sys::fuzz_target;
use phx_analyze_engine::corruption;
use phx_analyze_engine::model::{HashType, IntegrityResult};
use phx_analyze_engine::pipeline::format_detection;
use phx_analyze_engine::reader::DataSource;

fuzz_target!(|data: &[u8]| {
    let src = DataSource::from_bytes("fuzz", data.to_vec());
    let format = format_detection::detect(&src);
    let integrity = IntegrityResult::without_manifest(HashType::Sha256, "0".into());
    let _ = corruption::scan(&src, format, &integrity, true, 1_000);
});
