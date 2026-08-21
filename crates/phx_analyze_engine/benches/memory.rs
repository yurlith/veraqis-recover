//! Block-hashing benchmark — exercises the per-block path that bounds memory.
//!
//! Run with `cargo bench -p phx_analyze_engine --bench memory`.

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use phx_analyze_engine::integrity::{hash_source, MAX_BLOCKS};
use phx_analyze_engine::model::HashType;
use phx_analyze_engine::reader::DataSource;

fn bench_block_hashing(c: &mut Criterion) {
    let bytes = vec![0xA5u8; 16 * 1024 * 1024];
    let src = DataSource::from_bytes("bench", bytes);

    let mut group = c.benchmark_group("block_hashing");
    group.throughput(Throughput::Bytes(16 * 1024 * 1024));
    group.bench_function("sha256_64kib_blocks", |b| {
        b.iter(|| hash_source(&src, HashType::Sha256, Some(64 * 1024), MAX_BLOCKS).unwrap())
    });
    group.finish();
}

criterion_group!(benches, bench_block_hashing);
criterion_main!(benches);
