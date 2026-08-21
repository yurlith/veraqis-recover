# veraqis-recover

An open-source structural recovery engine and CLI for damaged archive files,
from the team behind [VERAQIS](https://veraqis.tech).

It repairs **ZIP, gzip, tar, RAR5, and 7z** containers by reconstructing the
structure that survived — a central directory rebuilt from local headers, a
gzip stream resynced past a corrupted member, a 7z signature restored under
its own checksum. Every recovered byte is independently checked against a
checksum the format itself carries (CRC-32, structural checksums); nothing is
reported as recovered on a guess. When a file is too damaged for anything
here to prove, the tool says so and writes nothing, rather than emitting a
plausible-looking but unverified result.

## What this is (and isn't)

This is the open structural-repair core of a larger recovery engine
maintained as a commercial product. It is deliberately narrow:

- **In scope:** structural repair for ZIP/gzip/tar/RAR5/7z, CRC/checksum
  verification, a repair report you can inspect.
- **Out of scope, on purpose:** deeper, format-specific recovery (e.g.
  reconstructing a SQLite database's rows, a PDF's object graph, or an
  Office document's package structure), cryptographic recovery certificates,
  and any licensing or tiered-feature logic. None of that lives in this
  repository. What's here is complete and useful on its own — it's not a
  crippled demo of something else.

If you need those deeper capabilities, they exist in the commercial product
this engine is a subset of; this repository doesn't try to sell you that —
it's here so you can read the code, verify the claims above yourself, and
use the structural-repair core freely under a permissive license.

## Quick start

```sh
cargo build --release
./target/release/veraqis-recover path/to/damaged.zip --output ./recovered
```

Without `--output`, it analyzes and reports without writing anything
(a dry run). Example output on a ZIP with a truncated central directory:

```
veraqis-recover: damaged.zip — structural damage detected
  - ZIP_EOCD_001 (Catastrophic)
veraqis-recover: recovery succeeded — 17679 byte(s) verified-recovered, 0 byte(s) lost
  note: rebuilt central directory for 4 member(s) from local headers
```

Recovery also writes a `.phxr.json` sidecar next to the output: a signed,
inspectable record of exactly what was changed, per file, with the evidence
behind each entry (was it independently attested by a surviving central
directory, or only self-consistent with its own header?). The signing key is
ephemeral per run unless you provide one — there is no vendor key, and
nothing here calls out to a network.

## Workspace layout

| Crate | What it does |
|---|---|
| `phx_format_id` | Identifies a file's format from its bytes and, separately, its name. |
| `phx_zip_core` | Format-detection/evidence core for ZIP-family containers (no filesystem, no threads). |
| `phx_analyze_engine` | Damage detection, health scoring, integrity checks. |
| `phx_recovery` | The structural repair strategies themselves. |
| `veraqis_recover` | This CLI. |
| `phx_test_utils` | Shared test fixtures (dev-only). |

## Building

Rust 1.85+ (see `rust-toolchain.toml`). Standard workspace:

```sh
cargo build --workspace
cargo test --workspace
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.
