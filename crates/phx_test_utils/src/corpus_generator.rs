//! `CorpusGenerator` — produces deterministic, reproducible damaged files plus
//! their [`CorpusEntry`] ground-truth metadata (CLAUDE.md Phase 1, Step 1.3).
//!
//! Every method takes a clean source, applies one well-defined mutation keyed
//! by the entry `id` and the generator's `rng_seed`, writes the damaged file
//! under `testdata/<format>/<subdir>/<id>.<ext>`, and returns the metadata
//! describing the expected analysis result.
//!
//! Reachable as `phx_test_utils::generators::CorpusGenerator`.

use std::io;
use std::path::PathBuf;

use serde_json::{json, Value};

use crate::corpus::{CorpusEntry, ExpectedCorruption, GroundTruth, SplitMix64};

/// Deterministic corruption generator for one format + clean source.
pub struct CorpusGenerator {
    /// Root `testdata/` directory.
    pub testdata_root: PathBuf,
    /// Format label, e.g. `"ZIP"`.
    pub format: String,
    /// Short corpus directory for this format, e.g. `"zip"`, `"gz"`, `"bz2"`.
    pub dir: String,
    /// File extension without the dot, e.g. `"zip"`.
    pub ext: String,
    /// Clean source bytes the mutations are derived from.
    pub source: Vec<u8>,
    /// Fixed seed → reproducible corpus.
    pub rng_seed: u64,
}

/// Internal description of one generated entry, assembled by each method.
struct Spec {
    subdir: &'static str,
    corruption_type: &'static str,
    method: &'static str,
    params: Value,
    rule_id: &'static str,
    category: &'static str,
    severity: &'static str,
    affected_field: &'static str,
    off_range: [u64; 2],
    health: [u8; 2],
    recover: &'static str,
    opens: bool,
    extract_pct: u8,
    tags: Vec<&'static str>,
}

impl CorpusGenerator {
    pub fn new(
        testdata_root: impl Into<PathBuf>,
        format: impl Into<String>,
        dir: impl Into<String>,
        ext: impl Into<String>,
        source: Vec<u8>,
        rng_seed: u64,
    ) -> Self {
        CorpusGenerator {
            testdata_root: testdata_root.into(),
            format: format.into(),
            dir: dir.into(),
            ext: ext.into(),
            source,
            rng_seed,
        }
    }

    fn rng(&self, id: &str) -> SplitMix64 {
        SplitMix64::keyed(self.rng_seed, id)
    }

    /// Write the damaged bytes and assemble the [`CorpusEntry`].
    fn emit(&self, id: &str, bytes: Vec<u8>, spec: Spec) -> io::Result<CorpusEntry> {
        let rel = format!("{}/{}/{id}.{}", self.dir, spec.subdir, self.ext);
        let abs = self.testdata_root.join(&rel);
        if let Some(parent) = abs.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&abs, &bytes)?;

        let verify_cmd = self.verify_cmd_template().replace("{file}", &rel);

        Ok(CorpusEntry {
            id: id.to_string(),
            file: rel,
            format: self.format.clone(),
            corruption_class: "single".to_string(),
            corruption_type: spec.corruption_type.to_string(),
            generator_method: spec.method.to_string(),
            generator_params: spec.params,
            expected_corruptions: vec![ExpectedCorruption {
                category: spec.category.to_string(),
                severity: spec.severity.to_string(),
                rule_id: spec.rule_id.to_string(),
                affected_field: spec.affected_field.to_string(),
                approximate_offset_range: spec.off_range,
            }],
            expected_health_range: spec.health,
            expected_recoverability: spec.recover.to_string(),
            expected_opens: spec.opens,
            expected_extractable_pct: spec.extract_pct,
            ground_truth: GroundTruth {
                tool_verify_cmd: verify_cmd,
                ..Default::default()
            },
            compound: false,
            compound_ids: Vec::new(),
            tags: spec.tags.into_iter().map(String::from).collect(),
        })
    }

    fn verify_cmd_template(&self) -> &'static str {
        match self.format.as_str() {
            "ZIP" => "unzip -t {file}",
            "TAR" => "tar -tvf {file}",
            "ISO" => "isoinfo -d -i {file}",
            "GZIP" => "gzip -t {file}",
            "BZIP2" => "bzip2 -t {file}",
            "XZ" => "xz -t {file}",
            "ZSTD" => "zstd -t {file}",
            "LZ4" => "lz4 -t {file}",
            "RAR" => "unrar t {file}",
            "7Z" => "7z t {file}",
            "PDF" => "pdfinfo {file}",
            "SQLite" => "sqlite3 {file} \"PRAGMA integrity_check\"",
            _ => "true {file}",
        }
    }

    // ── Universal mutators ──────────────────────────────────────────────────

    /// Truncate the last `pct` fraction of bytes (e.g. 0.05 = drop last 5%).
    pub fn truncate_tail_pct(&self, pct: f64, id: &str) -> io::Result<CorpusEntry> {
        let keep = ((self.source.len() as f64) * (1.0 - pct)).floor() as usize;
        let bytes = self.source[..keep.min(self.source.len())].to_vec();
        let (severity, health, recover, opens) = trunc_grades(pct);
        self.emit(
            id,
            bytes,
            Spec {
                subdir: "truncated",
                corruption_type: "TRUNCATION_TAIL",
                method: "truncate_tail_pct",
                params: json!({ "pct": pct }),
                rule_id: trunc_rule(&self.format, pct, false),
                category: "Truncation",
                severity,
                affected_field: "stream.tail",
                off_range: [keep as u64, self.source.len() as u64],
                health,
                recover,
                opens,
                extract_pct: ((1.0 - pct) * 100.0) as u8,
                tags: vec!["truncation", "universal"],
            },
        )
    }

    /// Truncate the first `pct` fraction of bytes (destroys the header).
    pub fn truncate_head_pct(&self, pct: f64, id: &str) -> io::Result<CorpusEntry> {
        let drop = ((self.source.len() as f64) * pct).floor() as usize;
        let bytes = self.source[drop.min(self.source.len())..].to_vec();
        self.emit(
            id,
            bytes,
            Spec {
                subdir: "truncated",
                corruption_type: "TRUNCATION_HEAD",
                method: "truncate_head_pct",
                params: json!({ "pct": pct }),
                rule_id: trunc_rule(&self.format, pct, true),
                category: "Truncation",
                severity: "Catastrophic",
                affected_field: "stream.header",
                off_range: [0, drop as u64],
                health: [0, 19],
                recover: "None",
                opens: false,
                extract_pct: 0,
                tags: vec!["truncation", "header", "universal"],
            },
        )
    }

    /// Flip a single bit at an absolute `bit_offset`.
    pub fn bitflip_at(&self, bit_offset: u64, id: &str) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        let byte = (bit_offset / 8) as usize;
        let bit = (bit_offset % 8) as u8;
        if byte < bytes.len() {
            bytes[byte] ^= 1 << bit;
        }
        let in_header = byte < 512;
        self.emit(
            id,
            bytes,
            Spec {
                subdir: if in_header {
                    "bitflip_header"
                } else {
                    "bitflip_payload"
                },
                corruption_type: "BITFLIP_SINGLE",
                method: "bitflip_at",
                params: json!({ "bit_offset": bit_offset }),
                rule_id: flip_rule(&self.format, in_header, 1),
                category: "BitFlip",
                severity: if in_header { "Major" } else { "Minor" },
                affected_field: if in_header {
                    "header.bits"
                } else {
                    "payload.bits"
                },
                off_range: [byte as u64, byte as u64 + 1],
                health: if in_header { [50, 75] } else { [80, 99] },
                recover: "Medium",
                opens: !in_header,
                extract_pct: if in_header { 60 } else { 95 },
                tags: vec!["bitflip", "single"],
            },
        )
    }

    /// Flip `count` random bits in the payload area (offsets ≥ 512).
    pub fn random_bitflips_payload(&self, count: usize, id: &str) -> io::Result<CorpusEntry> {
        let mut rng = self.rng(id);
        let mut bytes = self.source.clone();
        let start = 512.min(bytes.len());
        let span = bytes.len().saturating_sub(start);
        if span > 0 {
            for _ in 0..count {
                let off = start + rng.below(span as u64) as usize;
                bytes[off] ^= 1 << (rng.below(8) as u8);
            }
        }
        self.emit(
            id,
            bytes,
            Spec {
                subdir: "bitflip_payload",
                corruption_type: "BITFLIP_MULTI",
                method: "random_bitflips_payload",
                params: json!({ "count": count }),
                rule_id: flip_rule(&self.format, false, count),
                category: "BitFlip",
                severity: if count > 5 { "Major" } else { "Minor" },
                affected_field: "payload.bits",
                off_range: [start as u64, bytes_len(&self.source)],
                health: if count > 5 { [50, 79] } else { [80, 99] },
                recover: "Medium",
                opens: true,
                extract_pct: 90,
                tags: vec!["bitflip", "multi", "payload"],
            },
        )
    }

    /// Flip `count` random bits anywhere (headers included).
    pub fn random_bitflips_anywhere(&self, count: usize, id: &str) -> io::Result<CorpusEntry> {
        let mut rng = self.rng(id);
        let mut bytes = self.source.clone();
        if !bytes.is_empty() {
            for _ in 0..count {
                let off = rng.below(bytes.len() as u64) as usize;
                bytes[off] ^= 1 << (rng.below(8) as u8);
            }
        }
        self.emit(
            id,
            bytes,
            Spec {
                subdir: "bitflip_header",
                corruption_type: "BITFLIP_ANYWHERE",
                method: "random_bitflips_anywhere",
                params: json!({ "count": count }),
                rule_id: flip_rule(&self.format, true, count),
                category: "BitFlip",
                severity: "Major",
                affected_field: "file.bits",
                off_range: [0, bytes_len(&self.source)],
                health: [40, 79],
                recover: "Low",
                opens: false,
                extract_pct: 50,
                tags: vec!["bitflip", "multi"],
            },
        )
    }

    /// Overwrite `[offset, offset+len)` with zero bytes.
    pub fn zero_range(&self, offset: u64, len: usize, id: &str) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        fill_range(&mut bytes, offset as usize, len, 0);
        self.emit(
            id,
            bytes,
            Spec {
                subdir: "sector_data_corrupt",
                corruption_type: "ZERO_RANGE",
                method: "zero_range",
                params: json!({ "offset": offset, "len": len }),
                rule_id: missing_rule(&self.format),
                category: "MissingData",
                severity: "Major",
                affected_field: "data.range",
                off_range: [offset, offset + len as u64],
                health: [30, 60],
                recover: "Low",
                opens: false,
                extract_pct: 50,
                tags: vec!["missing", "zeroed"],
            },
        )
    }

    /// Overwrite `[offset, offset+len)` with deterministic random bytes.
    pub fn random_bytes_range(&self, offset: u64, len: usize, id: &str) -> io::Result<CorpusEntry> {
        let mut rng = self.rng(id);
        let mut bytes = self.source.clone();
        let start = (offset as usize).min(bytes.len());
        let end = (start + len).min(bytes.len());
        for b in &mut bytes[start..end] {
            *b = (rng.below(256)) as u8;
        }
        self.emit(
            id,
            bytes,
            Spec {
                subdir: "sector_data_corrupt",
                corruption_type: "RANDOM_RANGE",
                method: "random_bytes_range",
                params: json!({ "offset": offset, "len": len }),
                rule_id: missing_rule(&self.format),
                category: "MissingData",
                severity: "Major",
                affected_field: "data.range",
                off_range: [offset, offset + len as u64],
                health: [30, 60],
                recover: "Low",
                opens: false,
                extract_pct: 50,
                tags: vec!["scrambled"],
            },
        )
    }

    /// Insert `bytes` at `offset` (grows the file, shifts the remainder).
    pub fn insert_bytes(&self, offset: u64, insert: &[u8], id: &str) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        let at = (offset as usize).min(bytes.len());
        bytes.splice(at..at, insert.iter().copied());
        self.emit(
            id,
            bytes,
            Spec {
                subdir: "sector_data_corrupt",
                corruption_type: "INSERT_BYTES",
                method: "insert_bytes",
                params: json!({ "offset": offset, "len": insert.len() }),
                rule_id: struct_rule(&self.format),
                category: "StructuralCorruption",
                severity: "Major",
                affected_field: "stream.layout",
                off_range: [offset, offset + insert.len() as u64],
                health: [30, 70],
                recover: "Low",
                opens: false,
                extract_pct: 40,
                tags: vec!["insertion", "shift"],
            },
        )
    }

    /// Delete `[offset, offset+len)` (shrinks the file).
    pub fn delete_range(&self, offset: u64, len: usize, id: &str) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        let start = (offset as usize).min(bytes.len());
        let end = (start + len).min(bytes.len());
        bytes.drain(start..end);
        self.emit(
            id,
            bytes,
            Spec {
                subdir: "sector_data_corrupt",
                corruption_type: "DELETE_RANGE",
                method: "delete_range",
                params: json!({ "offset": offset, "len": len }),
                rule_id: missing_rule(&self.format),
                category: "MissingData",
                severity: "Major",
                affected_field: "stream.layout",
                off_range: [offset, offset + len as u64],
                health: [25, 60],
                recover: "Low",
                opens: false,
                extract_pct: 40,
                tags: vec!["deletion", "shift"],
            },
        )
    }

    /// Swap two equal-length, non-overlapping ranges.
    pub fn swap_ranges(
        &self,
        offset_a: u64,
        offset_b: u64,
        len: usize,
        id: &str,
    ) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        let (a, b) = (offset_a as usize, offset_b as usize);
        if a + len <= bytes.len() && b + len <= bytes.len() && (a + len <= b || b + len <= a) {
            for i in 0..len {
                bytes.swap(a + i, b + i);
            }
        }
        self.emit(
            id,
            bytes,
            Spec {
                subdir: "block_reorder",
                corruption_type: "SWAP_RANGES",
                method: "swap_ranges",
                params: json!({ "offset_a": offset_a, "offset_b": offset_b, "len": len }),
                rule_id: reorder_rule(&self.format),
                category: "BlockReorder",
                severity: "Major",
                affected_field: "block.order",
                off_range: [offset_a.min(offset_b), offset_a.max(offset_b) + len as u64],
                health: [50, 75],
                recover: "Low",
                opens: false,
                extract_pct: 50,
                tags: vec!["reorder", "swap"],
            },
        )
    }

    /// Duplicate `[src, src+len)` and insert the copy at `dst`.
    pub fn duplicate_range(
        &self,
        src_offset: u64,
        len: usize,
        dst_offset: u64,
        id: &str,
    ) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        let s = src_offset as usize;
        if s + len <= bytes.len() {
            let chunk = bytes[s..s + len].to_vec();
            let at = (dst_offset as usize).min(bytes.len());
            bytes.splice(at..at, chunk);
        }
        self.emit(
            id,
            bytes,
            Spec {
                subdir: "sector_data_corrupt",
                corruption_type: "DUPLICATE_RANGE",
                method: "duplicate_range",
                params: json!({ "src_offset": src_offset, "len": len, "dst_offset": dst_offset }),
                rule_id: struct_rule(&self.format),
                category: "StructuralCorruption",
                severity: "Minor",
                affected_field: "stream.layout",
                off_range: [dst_offset, dst_offset + len as u64],
                health: [60, 85],
                recover: "Medium",
                opens: false,
                extract_pct: 70,
                tags: vec!["duplication"],
            },
        )
    }

    /// Simulate media failure: zero `sector_count` consecutive 512-byte sectors.
    pub fn media_sector_failure(
        &self,
        start_sector: u64,
        sector_count: usize,
        id: &str,
    ) -> io::Result<CorpusEntry> {
        let offset = start_sector * 512;
        let len = sector_count * 512;
        let mut e = self.zero_range(offset, len, id)?;
        e.corruption_type = "MEDIA_SECTOR_FAILURE".to_string();
        e.generator_method = "media_sector_failure".to_string();
        e.generator_params = json!({ "start_sector": start_sector, "sector_count": sector_count });
        e.tags.push("media-failure".to_string());
        Ok(e)
    }

    /// Simulate an interrupted write: cut the file at a random block boundary.
    pub fn interrupted_write(&self, id: &str) -> io::Result<CorpusEntry> {
        let mut rng = self.rng(id);
        let blocks = (self.source.len() / 512).max(1);
        let cut_block = rng.below(blocks as u64) as usize;
        let keep = (cut_block * 512).min(self.source.len());
        let bytes = self.source[..keep].to_vec();
        self.emit(
            id,
            bytes,
            Spec {
                subdir: "truncated",
                corruption_type: "INTERRUPTED_WRITE",
                method: "interrupted_write",
                params: json!({ "cut_block": cut_block }),
                rule_id: trunc_rule(&self.format, 0.5, false),
                category: "Truncation",
                severity: "Major",
                affected_field: "stream.tail",
                off_range: [keep as u64, self.source.len() as u64],
                health: [20, 60],
                recover: "Low",
                opens: false,
                extract_pct: 50,
                tags: vec!["truncation", "interrupted-write"],
            },
        )
    }
}

// ── ZIP-specific corruptions ────────────────────────────────────────────────

impl CorpusGenerator {
    /// Zero the EOCD signature (`PK\x05\x06` → `00 00 00 00`).
    pub fn zip_zero_eocd_signature(&self, id: &str) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        let eocd = zip_find_eocd(&bytes);
        if let Some(e) = eocd {
            bytes[e..e + 4].fill(0);
        }
        self.emit(
            id,
            bytes,
            Spec {
                subdir: "missing_eocd",
                corruption_type: "EOCD_SIGNATURE_ZEROED",
                method: "zip_zero_eocd_signature",
                params: json!({}),
                rule_id: "ZIP_EOCD_001",
                category: "StructuralCorruption",
                severity: "Catastrophic",
                affected_field: "EOCD.signature",
                off_range: [eocd.unwrap_or(0) as u64, eocd.unwrap_or(0) as u64 + 4],
                health: [0, 19],
                recover: "High",
                opens: false,
                extract_pct: 0,
                tags: vec!["eocd", "structural", "recoverable"],
            },
        )
    }

    /// Point `EOCD.cd_offset` beyond the end of the file.
    pub fn zip_eocd_cd_offset_oob(&self, id: &str) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        let eocd = zip_find_eocd(&bytes);
        if let Some(e) = eocd {
            let oob = (bytes.len() as u32).wrapping_add(0x1000);
            bytes[e + 16..e + 20].copy_from_slice(&oob.to_le_bytes());
        }
        self.emit(
            id,
            bytes,
            Spec {
                subdir: "missing_central_dir",
                corruption_type: "EOCD_CD_OFFSET_OOB",
                method: "zip_eocd_cd_offset_oob",
                params: json!({}),
                rule_id: "ZIP_EOCD_002",
                category: "StructuralCorruption",
                severity: "Major",
                affected_field: "EOCD.cd_offset",
                off_range: [eocd.unwrap_or(0) as u64 + 16, eocd.unwrap_or(0) as u64 + 20],
                health: [20, 50],
                recover: "High",
                opens: false,
                extract_pct: 30,
                tags: vec!["eocd", "offset", "oob"],
            },
        )
    }

    /// Corrupt the stored CRC-32 of central-directory entry `entry_index`.
    pub fn zip_corrupt_crc(&self, entry_index: usize, id: &str) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        let entries = zip_cd_entries(&bytes);
        let mut field = [0u64; 2];
        if let Some(e) = entries.get(entry_index) {
            let crc_pos = e.cd_pos + 16;
            // Deterministic-but-distinct wrong CRC per id, guaranteed to differ
            // from the original so repeated calls yield unique corpus files.
            let orig = u32::from_le_bytes([
                bytes[crc_pos],
                bytes[crc_pos + 1],
                bytes[crc_pos + 2],
                bytes[crc_pos + 3],
            ]);
            let mut newv = self.rng(id).next_u64() as u32;
            if newv == orig {
                newv ^= 0xFFFF_FFFF;
            }
            bytes[crc_pos..crc_pos + 4].copy_from_slice(&newv.to_le_bytes());
            field = [crc_pos as u64, crc_pos as u64 + 4];
        }
        self.emit(
            id,
            bytes,
            Spec {
                subdir: "bad_crc",
                corruption_type: "CRC_MISMATCH",
                method: "zip_corrupt_crc",
                params: json!({ "entry_index": entry_index }),
                rule_id: "ZIP_CRC_001",
                category: "ChecksumMismatch",
                severity: "Minor",
                affected_field: "CentralDirHeader.crc32",
                off_range: field,
                health: [85, 100],
                recover: "High",
                opens: true,
                extract_pct: 100,
                tags: vec!["crc", "minor", "recoverable", "single-entry"],
            },
        )
    }

    /// Overstate the compressed size of entry `entry_index` by `delta` bytes.
    pub fn zip_corrupt_compressed_size(
        &self,
        entry_index: usize,
        delta: i64,
        id: &str,
    ) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        let entries = zip_cd_entries(&bytes);
        let mut field = [0u64; 2];
        if let Some(e) = entries.get(entry_index) {
            let pos = e.cd_pos + 20;
            let cur =
                u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
            let new = (cur as i64 + delta).max(0) as u32;
            bytes[pos..pos + 4].copy_from_slice(&new.to_le_bytes());
            field = [pos as u64, pos as u64 + 4];
        }
        self.emit(
            id,
            bytes,
            Spec {
                subdir: "zip64_corrupted",
                corruption_type: "COMPRESSED_SIZE_WRONG",
                method: "zip_corrupt_compressed_size",
                params: json!({ "entry_index": entry_index, "delta": delta }),
                rule_id: "ZIP_SIZE_001",
                category: "StructuralCorruption",
                severity: "Major",
                affected_field: "CentralDirHeader.compressed_size",
                off_range: field,
                health: [40, 70],
                recover: "Medium",
                opens: false,
                extract_pct: 50,
                tags: vec!["size", "structural"],
            },
        )
    }

    /// Zero the entire central directory region (between cd_offset and EOCD).
    pub fn zip_remove_central_directory(&self, id: &str) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        let mut range = [0u64; 2];
        if let Some(e) = zip_find_eocd(&bytes) {
            let cd_offset =
                u32::from_le_bytes([bytes[e + 16], bytes[e + 17], bytes[e + 18], bytes[e + 19]])
                    as usize;
            if cd_offset < e {
                bytes[cd_offset..e].fill(0);
                range = [cd_offset as u64, e as u64];
            }
        }
        self.emit(
            id,
            bytes,
            Spec {
                subdir: "missing_central_dir",
                corruption_type: "CENTRAL_DIRECTORY_REMOVED",
                method: "zip_remove_central_directory",
                params: json!({}),
                rule_id: "ZIP_CD_001",
                category: "StructuralCorruption",
                severity: "Catastrophic",
                affected_field: "CentralDirectory",
                off_range: range,
                health: [0, 19],
                recover: "Medium",
                opens: false,
                extract_pct: 60,
                tags: vec!["central-dir", "catastrophic"],
            },
        )
    }

    /// Zero the local file header signature of entry `entry_index`.
    pub fn zip_corrupt_local_header_sig(
        &self,
        entry_index: usize,
        id: &str,
    ) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        let entries = zip_cd_entries(&bytes);
        let mut field = [0u64; 2];
        if let Some(e) = entries.get(entry_index) {
            let lfh = e.lfh_offset as usize;
            if lfh + 4 <= bytes.len() {
                bytes[lfh..lfh + 4].fill(0);
                field = [lfh as u64, lfh as u64 + 4];
            }
        }
        self.emit(
            id,
            bytes,
            Spec {
                subdir: "bitflip_header",
                corruption_type: "LOCAL_HEADER_SIG_INVALID",
                method: "zip_corrupt_local_header_sig",
                params: json!({ "entry_index": entry_index }),
                rule_id: "ZIP_LFH_001",
                category: "StructuralCorruption",
                severity: "Major",
                affected_field: "LocalFileHeader.signature",
                off_range: field,
                health: [40, 70],
                recover: "Medium",
                opens: false,
                extract_pct: 60,
                tags: vec!["lfh", "structural"],
            },
        )
    }

    /// Overflow the extra-field length of entry `entry_index` (set to 0xFFFF).
    pub fn zip_extra_field_overflow(
        &self,
        entry_index: usize,
        id: &str,
    ) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        let entries = zip_cd_entries(&bytes);
        let mut field = [0u64; 2];
        if let Some(e) = entries.get(entry_index) {
            let pos = e.cd_pos + 30;
            bytes[pos..pos + 2].copy_from_slice(&0xFFFFu16.to_le_bytes());
            field = [pos as u64, pos as u64 + 2];
        }
        self.emit(
            id,
            bytes,
            Spec {
                subdir: "extra_field_overflow",
                corruption_type: "EXTRA_FIELD_OVERFLOW",
                method: "zip_extra_field_overflow",
                params: json!({ "entry_index": entry_index }),
                rule_id: "ZIP_EXTRA_001",
                category: "StructuralCorruption",
                severity: "Minor",
                affected_field: "CentralDirHeader.extra_len",
                off_range: field,
                health: [70, 95],
                recover: "High",
                opens: true,
                extract_pct: 90,
                tags: vec!["extra-field", "minor"],
            },
        )
    }
}

// ── TAR-specific corruptions ────────────────────────────────────────────────

impl CorpusGenerator {
    /// Corrupt the UStar checksum field of the 512-byte block at `block_index`.
    pub fn tar_corrupt_checksum(&self, block_index: u64, id: &str) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        let base = (block_index * 512) as usize;
        let mut field = [0u64; 2];
        if base + 156 <= bytes.len() {
            for i in 148..156 {
                bytes[base + i] = b'9';
            }
            field = [base as u64 + 148, base as u64 + 156];
        }
        self.emit(
            id,
            bytes,
            Spec {
                subdir: "bad_ustar_checksum",
                corruption_type: "USTAR_CHECKSUM_INVALID",
                method: "tar_corrupt_checksum",
                params: json!({ "block_index": block_index }),
                rule_id: "TAR_UST_001",
                category: "StructuralCorruption",
                severity: "Major",
                affected_field: "UStarHeader.checksum",
                off_range: field,
                health: [60, 90],
                recover: "High",
                opens: true,
                extract_pct: 100,
                tags: vec!["ustar", "checksum"],
            },
        )
    }

    /// Remove the two-zero-block terminator at the end of the archive.
    pub fn tar_remove_terminator(&self, id: &str) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        let cut = bytes.len().saturating_sub(1024);
        bytes.truncate(cut);
        self.emit(
            id,
            bytes,
            Spec {
                subdir: "missing_terminator",
                corruption_type: "TERMINATOR_MISSING",
                method: "tar_remove_terminator",
                params: json!({}),
                rule_id: "TAR_TERM_001",
                category: "StructuralCorruption",
                severity: "Minor",
                affected_field: "Archive.terminator",
                off_range: [cut as u64, self.source.len() as u64],
                health: [85, 100],
                recover: "High",
                opens: true,
                extract_pct: 100,
                tags: vec!["terminator", "minor"],
            },
        )
    }

    /// Swap two 512-byte blocks (block reordering).
    pub fn tar_swap_blocks(&self, block_a: u64, block_b: u64, id: &str) -> io::Result<CorpusEntry> {
        self.swap_ranges(block_a * 512, block_b * 512, 512, id)
            .map(|mut e| {
                e.corruption_type = "TAR_BLOCK_SWAP".to_string();
                e.generator_method = "tar_swap_blocks".to_string();
                e.generator_params = json!({ "block_a": block_a, "block_b": block_b });
                e
            })
    }

    /// Overstate the size field of entry `entry_index` by `delta`, fixing the
    /// header checksum so the size is the only invalid signal.
    pub fn tar_overstate_size(
        &self,
        entry_index: usize,
        delta: u64,
        id: &str,
    ) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        let headers = tar_header_offsets(&bytes);
        let mut field = [0u64; 2];
        if let Some(&off) = headers.get(entry_index) {
            let base = off as usize;
            let cur = tar_parse_octal(&bytes[base + 124..base + 136]).unwrap_or(0);
            let new = cur + delta;
            let s = format!("{new:011o}\0");
            bytes[base + 124..base + 124 + s.len().min(12)]
                .copy_from_slice(&s.as_bytes()[..s.len().min(12)]);
            tar_fix_checksum(&mut bytes[base..base + 512]);
            field = [base as u64 + 124, base as u64 + 136];
        }
        self.emit(
            id,
            bytes,
            Spec {
                subdir: "wrong_size_field",
                corruption_type: "SIZE_OVERSTATED",
                method: "tar_overstate_size",
                params: json!({ "entry_index": entry_index, "delta": delta }),
                rule_id: "TAR_SIZE_001",
                category: "StructuralCorruption",
                severity: "Major",
                affected_field: "UStarHeader.size",
                off_range: field,
                health: [50, 80],
                recover: "Medium",
                opens: false,
                extract_pct: 60,
                tags: vec!["size", "structural"],
            },
        )
    }
}

// ── ISO-specific corruptions ────────────────────────────────────────────────

impl CorpusGenerator {
    /// Zero the PVD magic (`CD001` at offset 32769).
    pub fn iso_zero_pvd_magic(&self, id: &str) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        let magic = 32769usize;
        if magic + 5 <= bytes.len() {
            bytes[magic..magic + 5].fill(0);
        }
        self.emit(
            id,
            bytes,
            Spec {
                subdir: "bad_pvd",
                corruption_type: "PVD_MAGIC_ZEROED",
                method: "iso_zero_pvd_magic",
                params: json!({}),
                rule_id: "ISO_PVD_001",
                category: "StructuralCorruption",
                severity: "Catastrophic",
                affected_field: "PrimaryVolumeDescriptor.magic",
                off_range: [magic as u64, magic as u64 + 5],
                health: [0, 19],
                recover: "Medium",
                opens: false,
                extract_pct: 40,
                tags: vec!["pvd", "catastrophic"],
            },
        )
    }

    /// Point the L-path-table location beyond the end of the image.
    pub fn iso_path_table_oob(&self, id: &str) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        let pvd = 16 * 2048;
        let pos = pvd + 140;
        if pos + 4 <= bytes.len() {
            let huge = (bytes.len() as u32 / 2048).wrapping_add(0x1000);
            bytes[pos..pos + 4].copy_from_slice(&huge.to_le_bytes());
        }
        self.emit(
            id,
            bytes,
            Spec {
                subdir: "path_table_offset_oob",
                corruption_type: "PATH_TABLE_OOB",
                method: "iso_path_table_oob",
                params: json!({}),
                rule_id: "ISO_PT_001",
                category: "MissingData",
                severity: "Major",
                affected_field: "PrimaryVolumeDescriptor.path_table_location",
                off_range: [pos as u64, pos as u64 + 4],
                health: [30, 60],
                recover: "Medium",
                opens: false,
                extract_pct: 55,
                tags: vec!["path-table", "oob"],
            },
        )
    }
}

// ── Compound corruptions (two simultaneous faults) ──────────────────────────

impl CorpusGenerator {
    /// Emit an entry carrying two or more expected corruptions.
    #[allow(clippy::too_many_arguments)]
    fn emit_compound(
        &self,
        id: &str,
        bytes: Vec<u8>,
        subdir: &str,
        corruption_type: &str,
        method: &str,
        params: Value,
        corruptions: Vec<ExpectedCorruption>,
        health: [u8; 2],
        recover: &str,
        opens: bool,
        extract_pct: u8,
        tags: Vec<&str>,
    ) -> io::Result<CorpusEntry> {
        let rel = format!("{}/{subdir}/{id}.{}", self.dir, self.ext);
        let abs = self.testdata_root.join(&rel);
        if let Some(parent) = abs.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&abs, &bytes)?;
        let verify_cmd = self.verify_cmd_template().replace("{file}", &rel);

        Ok(CorpusEntry {
            id: id.to_string(),
            file: rel,
            format: self.format.clone(),
            corruption_class: "compound".to_string(),
            corruption_type: corruption_type.to_string(),
            generator_method: method.to_string(),
            generator_params: params,
            expected_corruptions: corruptions,
            expected_health_range: health,
            expected_recoverability: recover.to_string(),
            expected_opens: opens,
            expected_extractable_pct: extract_pct,
            ground_truth: GroundTruth {
                tool_verify_cmd: verify_cmd,
                ..Default::default()
            },
            compound: true,
            compound_ids: Vec::new(),
            tags: tags.into_iter().map(String::from).collect(),
        })
    }

    /// ZIP compound: missing EOCD signature **and** a CRC mismatch.
    pub fn zip_compound_eocd_crc(&self, id: &str) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        let mut corrs = Vec::new();
        if let Some(e) = zip_cd_entries(&bytes).first() {
            let crc_pos = e.cd_pos + 16;
            let newv = self.rng(id).next_u64() as u32 | 1;
            bytes[crc_pos..crc_pos + 4].copy_from_slice(&newv.to_le_bytes());
            corrs.push(expected(
                "ChecksumMismatch",
                "Minor",
                "ZIP_CRC_001",
                "CentralDirHeader.crc32",
                [crc_pos as u64, crc_pos as u64 + 4],
            ));
        }
        if let Some(eocd) = zip_find_eocd(&bytes) {
            bytes[eocd..eocd + 4].fill(0);
            corrs.push(expected(
                "StructuralCorruption",
                "Catastrophic",
                "ZIP_EOCD_001",
                "EOCD.signature",
                [eocd as u64, eocd as u64 + 4],
            ));
        }
        self.emit_compound(
            id,
            bytes,
            "missing_eocd",
            "COMPOUND_EOCD_CRC",
            "zip_compound_eocd_crc",
            json!({}),
            corrs,
            [0, 19],
            "Medium",
            false,
            50,
            vec!["compound", "eocd", "crc", "catastrophic"],
        )
    }

    /// ZIP compound: tail truncation **and** a payload bit flip.
    pub fn zip_compound_trunc_bitflip(&self, id: &str) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        let mut rng = self.rng(id);
        if bytes.len() > 600 {
            let off = 512 + rng.below((bytes.len() - 600) as u64) as usize;
            bytes[off] ^= 1 << (rng.below(8) as u8);
        }
        let keep = ((bytes.len() as f64) * 0.95).floor() as usize;
        bytes.truncate(keep);
        let corrs = vec![
            expected(
                "Truncation",
                "Major",
                "ZIP_TRUNC_002",
                "stream.tail",
                [keep as u64, self.source.len() as u64],
            ),
            expected(
                "BitFlip",
                "Minor",
                "ZIP_FLIP_001",
                "payload.bits",
                [512, keep as u64],
            ),
        ];
        self.emit_compound(
            id,
            bytes,
            "truncated",
            "COMPOUND_TRUNC_BITFLIP",
            "zip_compound_trunc_bitflip",
            json!({ "pct": 0.05 }),
            corrs,
            [20, 49],
            "Low",
            false,
            50,
            vec!["compound", "truncation", "bitflip"],
        )
    }

    /// TAR compound: bad UStar checksum **and** tail truncation.
    pub fn tar_compound_checksum_trunc(&self, id: &str) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        if bytes.len() > 156 {
            for b in &mut bytes[148..156] {
                *b = b'9';
            }
        }
        let keep = ((bytes.len() as f64) * 0.90).floor() as usize;
        let cut_from = keep as u64;
        bytes.truncate(keep);
        let corrs = vec![
            expected(
                "StructuralCorruption",
                "Major",
                "TAR_UST_001",
                "UStarHeader.checksum",
                [148, 156],
            ),
            expected(
                "Truncation",
                "Major",
                "TAR_TRUNC_002",
                "stream.tail",
                [cut_from, self.source.len() as u64],
            ),
        ];
        self.emit_compound(
            id,
            bytes,
            "bad_ustar_checksum",
            "COMPOUND_CHECKSUM_TRUNC",
            "tar_compound_checksum_trunc",
            json!({ "pct": 0.10 }),
            corrs,
            [20, 49],
            "Low",
            false,
            50,
            vec!["compound", "checksum", "truncation"],
        )
    }

    /// ISO compound: zeroed PVD magic **and** tail truncation.
    pub fn iso_compound_pvd_trunc(&self, id: &str) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        if bytes.len() > 32774 {
            bytes[32769..32774].fill(0);
        }
        let keep = ((bytes.len() as f64) * 0.80).floor() as usize;
        let cut_from = keep as u64;
        bytes.truncate(keep);
        let corrs = vec![
            expected(
                "StructuralCorruption",
                "Catastrophic",
                "ISO_PVD_001",
                "PrimaryVolumeDescriptor.magic",
                [32769, 32774],
            ),
            expected(
                "Truncation",
                "Catastrophic",
                "ISO_TRUNC_002",
                "stream.tail",
                [cut_from, self.source.len() as u64],
            ),
        ];
        self.emit_compound(
            id,
            bytes,
            "bad_pvd",
            "COMPOUND_PVD_TRUNC",
            "iso_compound_pvd_trunc",
            json!({ "pct": 0.20 }),
            corrs,
            [0, 19],
            "None",
            false,
            20,
            vec!["compound", "pvd", "truncation", "catastrophic"],
        )
    }
}

/// Build an [`ExpectedCorruption`] tersely.
fn expected(
    category: &str,
    severity: &str,
    rule_id: &str,
    affected_field: &str,
    off_range: [u64; 2],
) -> ExpectedCorruption {
    ExpectedCorruption {
        category: category.to_string(),
        severity: severity.to_string(),
        rule_id: rule_id.to_string(),
        affected_field: affected_field.to_string(),
        approximate_offset_range: off_range,
    }
}

/// Rule-id prefix for a format.
fn prefix(format: &str) -> &'static str {
    match format {
        "ZIP" => "ZIP",
        "TAR" => "TAR",
        "ISO" => "ISO",
        "GZIP" => "GZ",
        "BZIP2" => "BZ2",
        "XZ" => "XZ",
        "ZSTD" => "ZST",
        "LZ4" => "LZ4",
        "RAR" => "RAR",
        "7Z" => "7Z",
        "PDF" => "PDF",
        "SQLite" => "SQ",
        _ => "GEN",
    }
}

/// Subdirectory for a signature/magic corruption, per format.
fn magic_subdir(format: &str) -> &'static str {
    match format {
        "GZIP" | "LZ4" => "bad_magic",
        "BZIP2" => "bad_stream_magic",
        "XZ" => "bad_stream_header",
        "ZSTD" => "bad_frame_magic",
        "RAR" => "rar5_signature_corrupt",
        "7Z" => "bad_signature_header",
        "PDF" => "bad_header",
        "SQLite" => "bad_magic",
        _ => "bitflip_header",
    }
}

// ── Generalized emitter + planned-format / remaining corruptions ─────────────

impl CorpusGenerator {
    /// Generalized single-or-multi emitter with owned (dynamic) rule ids.
    #[allow(clippy::too_many_arguments)]
    fn emit_with(
        &self,
        id: &str,
        bytes: Vec<u8>,
        subdir: &str,
        corruption_type: &str,
        method: &str,
        params: Value,
        class: &str,
        corruptions: Vec<ExpectedCorruption>,
        health: [u8; 2],
        recover: &str,
        opens: bool,
        extract_pct: u8,
        tags: Vec<&str>,
    ) -> io::Result<CorpusEntry> {
        let rel = format!("{}/{subdir}/{id}.{}", self.dir, self.ext);
        let abs = self.testdata_root.join(&rel);
        if let Some(parent) = abs.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&abs, &bytes)?;
        let verify_cmd = self.verify_cmd_template().replace("{file}", &rel);
        Ok(CorpusEntry {
            id: id.to_string(),
            file: rel,
            format: self.format.clone(),
            corruption_class: class.to_string(),
            corruption_type: corruption_type.to_string(),
            generator_method: method.to_string(),
            generator_params: params,
            expected_corruptions: corruptions,
            expected_health_range: health,
            expected_recoverability: recover.to_string(),
            expected_opens: opens,
            expected_extractable_pct: extract_pct,
            ground_truth: GroundTruth {
                tool_verify_cmd: verify_cmd,
                ..Default::default()
            },
            compound: class == "compound",
            compound_ids: Vec::new(),
            tags: tags.into_iter().map(String::from).collect(),
        })
    }

    /// Zero the leading `sig_len`-byte signature/magic (any format).
    pub fn corrupt_magic(&self, sig_len: usize, id: &str) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        let n = sig_len.min(bytes.len());
        bytes[..n].fill(0);
        let rule = format!("{}_MAGIC_001", prefix(&self.format));
        self.emit_with(
            id,
            bytes,
            magic_subdir(&self.format),
            "MAGIC_ZEROED",
            "corrupt_magic",
            json!({ "sig_len": sig_len }),
            "single",
            vec![expected(
                "StructuralCorruption",
                "Catastrophic",
                &rule,
                "signature",
                [0, n as u64],
            )],
            [0, 19],
            "None",
            false,
            0,
            vec!["magic", "signature", "catastrophic"],
        )
    }

    /// Corrupt the trailing `len`-byte checksum/length trailer (gz/zstd/xz/lz4).
    pub fn corrupt_trailing_checksum(&self, len: usize, id: &str) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        let total = bytes.len();
        let start = total.saturating_sub(len);
        let mut rng = self.rng(id);
        for b in &mut bytes[start..total] {
            *b ^= (rng.below(255) as u8) | 1;
        }
        let rule = format!("{}_CRC_001", prefix(&self.format));
        self.emit_with(
            id,
            bytes,
            "bad_checksum",
            "TRAILER_CHECKSUM",
            "corrupt_trailing_checksum",
            json!({ "len": len }),
            "single",
            vec![expected(
                "ChecksumMismatch",
                "Major",
                &rule,
                "trailer.checksum",
                [start as u64, total as u64],
            )],
            [40, 75],
            "Medium",
            false,
            60,
            vec!["checksum", "trailer"],
        )
    }

    // ── GZIP-specific ────────────────────────────────────────────────────────

    /// Replace the GZIP magic (`1F 8B`) with zeroes.
    pub fn gz_corrupt_magic(&self, id: &str) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        if bytes.len() >= 2 {
            bytes[0] = 0;
            bytes[1] = 0;
        }
        self.emit_with(
            id,
            bytes,
            "bad_magic",
            "GZ_MAGIC",
            "gz_corrupt_magic",
            json!({}),
            "single",
            vec![expected(
                "StructuralCorruption",
                "Catastrophic",
                "GZ_MAGIC_001",
                "gzip.magic",
                [0, 2],
            )],
            [0, 19],
            "None",
            false,
            0,
            vec!["gzip", "magic", "catastrophic"],
        )
    }

    /// Corrupt the GZIP ISIZE trailer (last 4 bytes = uncompressed size).
    pub fn gz_corrupt_isize(&self, id: &str) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        let n = bytes.len();
        if n >= 4 {
            for b in &mut bytes[n - 4..] {
                *b ^= 0xFF;
            }
        }
        self.emit_with(
            id,
            bytes,
            "bad_isize",
            "GZ_ISIZE",
            "gz_corrupt_isize",
            json!({}),
            "single",
            vec![expected(
                "StructuralCorruption",
                "Minor",
                "GZ_ISIZE_001",
                "gzip.isize",
                [(n as u64).saturating_sub(4), n as u64],
            )],
            [70, 95],
            "High",
            true,
            100,
            vec!["gzip", "isize", "minor"],
        )
    }

    /// Corrupt the GZIP CRC32 trailer (bytes [len-8, len-4)).
    pub fn gz_corrupt_trailer_crc(&self, id: &str) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        let n = bytes.len();
        if n >= 8 {
            for b in &mut bytes[n - 8..n - 4] {
                *b ^= 0xFF;
            }
        }
        self.emit_with(
            id,
            bytes,
            "bad_content_crc32",
            "GZ_CRC",
            "gz_corrupt_trailer_crc",
            json!({}),
            "single",
            vec![expected(
                "ChecksumMismatch",
                "Major",
                "GZ_ICRC_001",
                "gzip.crc32",
                [(n as u64).saturating_sub(8), (n as u64).saturating_sub(4)],
            )],
            [40, 70],
            "Medium",
            false,
            85,
            vec!["gzip", "crc", "major"],
        )
    }

    // ── PDF-specific ───────────────────────────────────────────────────────--

    /// Replace the `%PDF-` header with garbage.
    pub fn pdf_corrupt_header(&self, id: &str) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        let n = 5.min(bytes.len());
        bytes[..n].copy_from_slice(&b"%ZZZ-"[..n]);
        self.emit_with(
            id,
            bytes,
            "bad_header",
            "PDF_HEADER",
            "pdf_corrupt_header",
            json!({}),
            "single",
            vec![expected(
                "StructuralCorruption",
                "Catastrophic",
                "PDF_HDR_001",
                "pdf.header",
                [0, n as u64],
            )],
            [0, 19],
            "None",
            false,
            0,
            vec!["pdf", "header", "catastrophic"],
        )
    }

    /// Delete the trailing `%%EOF` marker.
    pub fn pdf_remove_eof_marker(&self, id: &str) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        let range = find_subslice(&bytes, b"%%EOF").map(|p| (p, p + 5));
        if let Some((s, e)) = range {
            bytes.drain(s..e);
        }
        let off = range.map(|(s, _)| s as u64).unwrap_or(0);
        self.emit_with(
            id,
            bytes,
            "missing_eof_marker",
            "PDF_EOF",
            "pdf_remove_eof_marker",
            json!({}),
            "single",
            vec![expected(
                "StructuralCorruption",
                "Major",
                "PDF_EOF_001",
                "pdf.eof",
                [off, off + 5],
            )],
            [50, 80],
            "High",
            true,
            95,
            vec!["pdf", "eof", "major"],
        )
    }

    /// Corrupt the `startxref` offset (point it to a wrong position).
    pub fn pdf_corrupt_startxref(&self, id: &str) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        let mut off = 0u64;
        if let Some(p) = find_subslice(&bytes, b"startxref") {
            // Overwrite the digits following startxref (after the newline).
            let mut i = p + 9;
            while i < bytes.len() && (bytes[i] == b'\r' || bytes[i] == b'\n' || bytes[i] == b' ') {
                i += 1;
            }
            off = i as u64;
            let mut j = i;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                bytes[j] = b'9';
                j += 1;
            }
        }
        self.emit_with(
            id,
            bytes,
            "bad_xref_offset",
            "PDF_STARTXREF",
            "pdf_corrupt_startxref",
            json!({}),
            "single",
            vec![expected(
                "StructuralCorruption",
                "Major",
                "PDF_XREF_001",
                "pdf.startxref",
                [off, off + 8],
            )],
            [40, 70],
            "Medium",
            false,
            70,
            vec!["pdf", "xref", "major"],
        )
    }

    /// Zero the first `count` xref table entry lines.
    pub fn pdf_zero_xref_entries(&self, count: usize, id: &str) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        let mut off = 0u64;
        if let Some(p) = find_subslice(&bytes, b"xref") {
            // xref entries are 20-byte fixed records after the subsection line.
            let mut i = p + 4;
            while i < bytes.len() && (bytes[i] == b'\r' || bytes[i] == b'\n') {
                i += 1;
            }
            // skip the subsection header line "0 N\n"
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            i += 1;
            off = i as u64;
            let end = (i + count * 20).min(bytes.len());
            for b in &mut bytes[i..end] {
                *b = b'0';
            }
        }
        self.emit_with(
            id,
            bytes,
            "missing_xref",
            "PDF_XREF_ZERO",
            "pdf_zero_xref_entries",
            json!({ "count": count }),
            "single",
            vec![expected(
                "MissingData",
                "Major",
                "PDF_XREF_002",
                "pdf.xref.entries",
                [off, off + (count as u64) * 20],
            )],
            [30, 60],
            "Medium",
            false,
            60,
            vec!["pdf", "xref", "missing"],
        )
    }

    // ── SQLite-specific ──────────────────────────────────────────────────────

    /// Zero the `SQLite format 3\0` magic header.
    pub fn sqlite_corrupt_magic(&self, id: &str) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        let n = 16.min(bytes.len());
        bytes[..n].fill(0);
        self.emit_with(
            id,
            bytes,
            "bad_magic",
            "SQ_MAGIC",
            "sqlite_corrupt_magic",
            json!({}),
            "single",
            vec![expected(
                "StructuralCorruption",
                "Catastrophic",
                "SQ_MAGIC_001",
                "sqlite.magic",
                [0, n as u64],
            )],
            [0, 19],
            "None",
            false,
            0,
            vec!["sqlite", "magic", "catastrophic"],
        )
    }

    /// Set the page-size field (bytes 16–17, big-endian) to a non-power-of-two.
    pub fn sqlite_corrupt_page_size(&self, id: &str) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        if bytes.len() >= 18 {
            bytes[16] = 0x03; // 1000 decimal, not a power of two
            bytes[17] = 0xE8;
        }
        self.emit_with(
            id,
            bytes,
            "bad_page_size",
            "SQ_PGSIZE",
            "sqlite_corrupt_page_size",
            json!({}),
            "single",
            vec![expected(
                "StructuralCorruption",
                "Catastrophic",
                "SQ_PGSIZE_001",
                "sqlite.page_size",
                [16, 18],
            )],
            [0, 19],
            "Low",
            false,
            30,
            vec!["sqlite", "page-size", "catastrophic"],
        )
    }

    /// Corrupt a B-tree page header type byte (page 1 header at offset 100).
    pub fn sqlite_corrupt_btree_page(&self, page_number: u32, id: &str) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        let page_size = if bytes.len() >= 18 {
            let ps = u16::from_be_bytes([bytes[16], bytes[17]]) as usize;
            if ps == 1 {
                65536
            } else {
                ps.max(512)
            }
        } else {
            4096
        };
        let hdr = if page_number <= 1 {
            100
        } else {
            (page_number as usize - 1) * page_size
        };
        if hdr < bytes.len() {
            bytes[hdr] = 0xFF; // invalid b-tree page type
        }
        self.emit_with(
            id,
            bytes,
            "btree_page_corrupt",
            "SQ_BTREE",
            "sqlite_corrupt_btree_page",
            json!({ "page_number": page_number }),
            "single",
            vec![expected(
                "StructuralCorruption",
                "Major",
                "SQ_BTREE_001",
                "sqlite.btree.page_type",
                [hdr as u64, hdr as u64 + 1],
            )],
            [30, 60],
            "Medium",
            false,
            60,
            vec!["sqlite", "btree", "major"],
        )
    }

    /// Corrupt the first-freelist-trunk-page pointer (header bytes 32–35).
    pub fn sqlite_corrupt_freelist(&self, id: &str) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        if bytes.len() >= 36 {
            bytes[32..36].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
        }
        self.emit_with(
            id,
            bytes,
            "freelist_corrupt",
            "SQ_FREELIST",
            "sqlite_corrupt_freelist",
            json!({}),
            "single",
            vec![expected(
                "StructuralCorruption",
                "Minor",
                "SQ_FREE_001",
                "sqlite.freelist_trunk",
                [32, 36],
            )],
            [60, 90],
            "High",
            true,
            95,
            vec!["sqlite", "freelist", "minor"],
        )
    }

    // ── Remaining ZIP/TAR/ISO-specific (best-effort on minimal files) ─────────

    /// Corrupt a ZIP64 EOCD locator if present; otherwise corrupt the EOCD
    /// comment-length field as a stand-in (our minimal files are not ZIP64).
    pub fn zip_corrupt_zip64_eocd(&self, id: &str) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        let mut off = 0u64;
        if let Some(p) = find_subslice(&bytes, &[0x50, 0x4B, 0x06, 0x07]) {
            bytes[p..p + 4].fill(0);
            off = p as u64;
        } else if let Some(eocd) = zip_find_eocd(&bytes) {
            let pos = eocd + 20; // comment length field
            if pos + 2 <= bytes.len() {
                bytes[pos..pos + 2].copy_from_slice(&0xFFFFu16.to_le_bytes());
                off = pos as u64;
            }
        }
        self.emit_with(
            id,
            bytes,
            "zip64_corrupted",
            "ZIP64_EOCD",
            "zip_corrupt_zip64_eocd",
            json!({}),
            "single",
            vec![expected(
                "StructuralCorruption",
                "Major",
                "ZIP_Z64_001",
                "ZIP64_EOCD_Locator.signature",
                [off, off + 4],
            )],
            [40, 70],
            "Medium",
            false,
            60,
            vec!["zip64", "structural"],
        )
    }

    /// Corrupt a GNU LongName ('L') block if present; otherwise turn the first
    /// header into a malformed longname block as a stand-in.
    pub fn tar_corrupt_gnu_longname(&self, id: &str) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        if bytes.len() >= 257 {
            bytes[156] = b'L'; // GNU longname typeflag
            bytes[0..8].fill(0); // damage the (now longname) name field
            tar_fix_checksum(&mut bytes[0..512]);
        }
        self.emit_with(
            id,
            bytes,
            "gnu_tar_longname_corrupt",
            "TAR_GNU_LONGNAME",
            "tar_corrupt_gnu_longname",
            json!({}),
            "single",
            vec![expected(
                "StructuralCorruption",
                "Major",
                "TAR_GNU_001",
                "GnuLongName.block",
                [0, 512],
            )],
            [40, 70],
            "Medium",
            false,
            60,
            vec!["tar", "gnu-longname", "structural"],
        )
    }

    /// Zero a directory-record length field in the root directory extent.
    pub fn iso_corrupt_dir_record_len(
        &self,
        record_index: usize,
        id: &str,
    ) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        // Root directory typically begins a few sectors after the PVD; our
        // minimal image has none, so target the PVD root-record area as a
        // stand-in (offset 156 within the PVD = root directory record).
        let pos = 16 * 2048 + 156 + record_index;
        if pos < bytes.len() {
            bytes[pos] = 0;
        }
        self.emit_with(
            id,
            bytes,
            "bad_directory_record",
            "ISO_DIR_LEN",
            "iso_corrupt_dir_record_len",
            json!({ "record_index": record_index }),
            "single",
            vec![expected(
                "StructuralCorruption",
                "Major",
                "ISO_DIR_001",
                "DirectoryRecord.length",
                [pos as u64, pos as u64 + 1],
            )],
            [40, 70],
            "Medium",
            false,
            60,
            vec!["iso", "dir-record", "structural"],
        )
    }

    /// Zero the supplementary volume descriptor (Joliet) at sector 17/18.
    pub fn iso_corrupt_svd(&self, id: &str) -> io::Result<CorpusEntry> {
        let mut bytes = self.source.clone();
        // SVD (type 2) would sit just after the PVD; zero its magic region.
        let pos = 17 * 2048 + 1;
        if pos + 5 <= bytes.len() {
            bytes[pos..pos + 5].fill(0);
        }
        self.emit_with(
            id,
            bytes,
            "bad_svd",
            "ISO_SVD",
            "iso_corrupt_svd",
            json!({}),
            "single",
            vec![expected(
                "StructuralCorruption",
                "Major",
                "ISO_SVD_001",
                "SupplementaryVolumeDescriptor.magic",
                [pos as u64, pos as u64 + 5],
            )],
            [50, 80],
            "Medium",
            true,
            80,
            vec!["iso", "svd", "joliet"],
        )
    }

    /// Apply two independent byte mutations to one file (generic compound).
    /// Each mutator returns the [`ExpectedCorruption`] it produced.
    pub fn compound_two<F, G>(
        &self,
        first: F,
        second: G,
        subdir: &str,
        id: &str,
    ) -> io::Result<CorpusEntry>
    where
        F: Fn(&mut Vec<u8>, &mut SplitMix64) -> ExpectedCorruption,
        G: Fn(&mut Vec<u8>, &mut SplitMix64) -> ExpectedCorruption,
    {
        let mut rng = self.rng(id);
        let mut bytes = self.source.clone();
        let c1 = first(&mut bytes, &mut rng);
        let c2 = second(&mut bytes, &mut rng);
        self.emit_with(
            id,
            bytes,
            subdir,
            "COMPOUND_TWO",
            "compound_two",
            json!({}),
            "compound",
            vec![c1, c2],
            [0, 49],
            "Low",
            false,
            40,
            vec!["compound"],
        )
    }
}

/// Find the first occurrence of `needle` in `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ── ZIP locating helpers ────────────────────────────────────────────────────

struct CdEntry {
    cd_pos: usize,
    lfh_offset: u32,
}

fn zip_find_eocd(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 22 {
        return None;
    }
    (0..=bytes.len() - 4).rev().find(|&i| {
        u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]) == 0x0605_4b50
    })
}

fn zip_cd_entries(bytes: &[u8]) -> Vec<CdEntry> {
    let mut out = Vec::new();
    let Some(eocd) = zip_find_eocd(bytes) else {
        return out;
    };
    let mut pos = u32::from_le_bytes([
        bytes[eocd + 16],
        bytes[eocd + 17],
        bytes[eocd + 18],
        bytes[eocd + 19],
    ]) as usize;
    while pos + 46 <= bytes.len()
        && u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]])
            == 0x0201_4b50
    {
        let name_len = u16::from_le_bytes([bytes[pos + 28], bytes[pos + 29]]) as usize;
        let extra_len = u16::from_le_bytes([bytes[pos + 30], bytes[pos + 31]]) as usize;
        let comment_len = u16::from_le_bytes([bytes[pos + 32], bytes[pos + 33]]) as usize;
        let lfh_offset = u32::from_le_bytes([
            bytes[pos + 42],
            bytes[pos + 43],
            bytes[pos + 44],
            bytes[pos + 45],
        ]);
        out.push(CdEntry {
            cd_pos: pos,
            lfh_offset,
        });
        pos += 46 + name_len + extra_len + comment_len;
    }
    out
}

// ── TAR locating helpers ────────────────────────────────────────────────────

fn tar_header_offsets(bytes: &[u8]) -> Vec<u64> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 512 <= bytes.len() {
        let block = &bytes[off..off + 512];
        if block.iter().all(|&b| b == 0) {
            break;
        }
        out.push(off as u64);
        let size = tar_parse_octal(&block[124..136]).unwrap_or(0);
        let data_blocks = size.div_ceil(512);
        off += 512 + (data_blocks as usize) * 512;
    }
    out
}

fn tar_parse_octal(field: &[u8]) -> Option<u64> {
    let s: String = field
        .iter()
        .take_while(|&&b| b != 0 && b != b' ')
        .map(|&b| b as char)
        .collect();
    u64::from_str_radix(s.trim(), 8).ok()
}

fn tar_fix_checksum(block: &mut [u8]) {
    for b in &mut block[148..156] {
        *b = b' ';
    }
    let sum: u64 = block.iter().map(|&b| b as u64).sum();
    let chk = format!("{sum:06o}\0 ");
    block[148..148 + chk.len()].copy_from_slice(chk.as_bytes());
}

// ── small byte helpers ──────────────────────────────────────────────────────

fn bytes_len(b: &[u8]) -> u64 {
    b.len() as u64
}

fn fill_range(bytes: &mut [u8], offset: usize, len: usize, value: u8) {
    let end = (offset + len).min(bytes.len());
    if offset < bytes.len() {
        for b in &mut bytes[offset..end] {
            *b = value;
        }
    }
}

// ── rule-id selection helpers (per-format, per-corruption) ───────────────────

fn trunc_rule(format: &str, pct: f64, head: bool) -> &'static str {
    match (format, head) {
        ("ZIP", true) => "ZIP_TRUNC_004",
        ("ZIP", false) if pct <= 0.01 => "ZIP_TRUNC_001",
        ("ZIP", false) if pct <= 0.05 => "ZIP_TRUNC_002",
        ("ZIP", false) => "ZIP_TRUNC_003",
        ("TAR", true) => "TAR_TRUNC_003",
        ("TAR", false) if pct <= 0.01 => "TAR_TRUNC_001",
        ("TAR", false) => "TAR_TRUNC_002",
        ("ISO", true) => "ISO_TRUNC_003",
        ("ISO", false) if pct <= 0.05 => "ISO_TRUNC_001",
        ("ISO", false) => "ISO_TRUNC_002",
        _ => "GEN_TRUNC_001",
    }
}

fn flip_rule(format: &str, header: bool, count: usize) -> &'static str {
    match (format, header, count) {
        ("ZIP", true, _) => "ZIP_FLIP_003",
        ("ZIP", false, c) if c > 5 => "ZIP_FLIP_002",
        ("ZIP", false, _) => "ZIP_FLIP_001",
        ("TAR", true, _) => "TAR_FLIP_002",
        ("TAR", false, _) => "TAR_FLIP_001",
        ("ISO", _, _) => "ISO_SECTOR_001",
        _ => "GEN_FLIP_001",
    }
}

fn missing_rule(format: &str) -> &'static str {
    match format {
        "ZIP" => "ZIP_CD_003",
        "TAR" => "TAR_SIZE_002",
        "ISO" => "ISO_SECTOR_002",
        _ => "GEN_MISSING_001",
    }
}

fn struct_rule(format: &str) -> &'static str {
    match format {
        "ZIP" => "ZIP_SIZE_001",
        "TAR" => "TAR_SIZE_001",
        "ISO" => "ISO_DIR_001",
        _ => "GEN_STRUCT_001",
    }
}

fn reorder_rule(format: &str) -> &'static str {
    match format {
        "TAR" => "TAR_BLOCK_001",
        _ => "GEN_REORDER_001",
    }
}

/// Severity / health / recoverability grading for tail truncation by fraction.
fn trunc_grades(pct: f64) -> (&'static str, [u8; 2], &'static str, bool) {
    if pct <= 0.01 {
        ("Minor", [80, 99], "High", true)
    } else if pct <= 0.05 {
        ("Major", [50, 79], "Medium", true)
    } else if pct <= 0.20 {
        ("Catastrophic", [20, 49], "Low", false)
    } else {
        ("Catastrophic", [0, 19], "None", false)
    }
}
