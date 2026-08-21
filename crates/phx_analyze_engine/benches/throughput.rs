//! Throughput benchmark for the single-pass integrity hasher.
//!
//! Run with `cargo bench -p phx_analyze_engine --bench throughput`.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use phx_analyze_engine::integrity::{hash_source, MAX_BLOCKS};
use phx_analyze_engine::model::HashType;
use phx_analyze_engine::reader::DataSource;

fn bench_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("integrity_hash");
    for size_mib in [1usize, 8, 32] {
        let bytes = vec![0x5Au8; size_mib * 1024 * 1024];
        let src = DataSource::from_bytes("bench", bytes);
        group.throughput(Throughput::Bytes((size_mib * 1024 * 1024) as u64));
        group.bench_with_input(BenchmarkId::new("sha256", size_mib), &src, |b, src| {
            b.iter(|| hash_source(src, HashType::Sha256, None, MAX_BLOCKS).unwrap())
        });
    }
    group.finish();
}

criterion_group!(benches, bench_hash);
criterion_main!(benches);
