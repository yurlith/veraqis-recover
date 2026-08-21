//! Reference-diff detection (Phase 2).
//!
//! Given a known-good reference (e.g. a backup of the clean file), diff a
//! damaged copy against it to identify the corruption precisely: truncation,
//! bit flips, zeroed/missing regions, signature damage. This is the mechanism
//! behind the spec's block-hash-based bitflip confidence and is exactly the
//! kind of comparison a recovery platform performs against a known-good copy.
//!
//! Rule-id selection mirrors the corpus generator's logic so findings line up
//! with `metadata.json` ground truth; `format` is the short label
//! (`"ZIP"`, `"GZIP"`, ...) derived from the file extension.

use crate::model::{ByteRange, CorruptionLocation};

use super::classifier::{DefectKind, Detected};

/// Map a file extension to a format label used for rule selection.
pub fn format_label_for_ext(ext: &str) -> &'static str {
    match ext.to_ascii_lowercase().as_str() {
        "zip" => "ZIP",
        "tar" => "TAR",
        "iso" => "ISO",
        "gz" => "GZIP",
        "bz2" => "BZIP2",
        "xz" => "XZ",
        "zst" => "ZSTD",
        "lz4" => "LZ4",
        "rar" => "RAR",
        "7z" => "7Z",
        "pdf" => "PDF",
        "db" | "sqlite" | "sqlite3" => "SQLite",
        _ => "*",
    }
}

/// ISO PVD magic lives at offset 32769 (sector 16 + 1), length 5.
const ISO_PVD_MAGIC: std::ops::Range<usize> = 32769..32774;

/// Diff `corrupted` against the known-good `clean`, emitting located findings.
pub fn diff(format: &str, corrupted: &[u8], clean: &[u8]) -> Vec<Detected> {
    let mut out = Vec::new();
    let (lc, ld) = (clean.len(), corrupted.len());

    // ── Length change ⇒ truncation (head/tail), middle deletion, or growth ──
    match ld.cmp(&lc) {
        std::cmp::Ordering::Less => {
            let pct = (lc - ld) as f64 / lc as f64;
            let prefix = corrupted == &clean[..ld]; // tail removed
            let suffix = corrupted == &clean[lc - ld..]; // head removed
            let removed = ByteRange::new(0, (lc - ld) as u64);
            let (rule, loc, range, what) = match (prefix, suffix) {
                (true, _) => (
                    tail_trunc_rule(format, pct),
                    CorruptionLocation::stream(ld as u64, lc as u64),
                    ByteRange::new(ld as u64, lc as u64),
                    "tail-truncated",
                ),
                (false, true) => (
                    head_trunc_rule(format),
                    CorruptionLocation::stream(0, (lc - ld) as u64),
                    removed,
                    "head-truncated",
                ),
                // Neither prefix nor suffix preserved ⇒ a middle region was deleted.
                (false, false) => (
                    missing_rule(format),
                    CorruptionLocation::stream(0, (lc - ld) as u64),
                    removed,
                    "middle-deleted",
                ),
            };
            out.push(
                Detected::new(DefectKind::ReferenceDiff, loc)
                    .with_rule(rule)
                    .with_range(range)
                    .with_detail(format!(
                        "{what} {:.1}% ({} of {} bytes)",
                        pct * 100.0,
                        lc - ld,
                        lc
                    )),
            );
        }
        std::cmp::Ordering::Greater => {
            out.push(
                Detected::new(
                    DefectKind::ReferenceDiff,
                    CorruptionLocation::stream(lc as u64, ld as u64),
                )
                .with_rule("GEN_STRUCT_001")
                .with_detail(format!("grew by {} bytes (insertion)", ld - lc)),
            );
        }
        std::cmp::Ordering::Equal => {}
    }

    // ── Byte-level diff over the common prefix (also catches damage that
    //    survived a truncation, e.g. a zeroed PVD in a truncated ISO) ──
    let common = lc.min(ld);
    let diffs: Vec<usize> = (0..common).filter(|&i| corrupted[i] != clean[i]).collect();
    if diffs.is_empty() {
        return out;
    }

    // ISO PVD magic damage is unambiguous regardless of other edits.
    if format == "ISO" && diffs.iter().any(|&i| ISO_PVD_MAGIC.contains(&i)) {
        let actual = corrupted[ISO_PVD_MAGIC].to_vec();
        let expected = clean[ISO_PVD_MAGIC].to_vec();
        out.push(
            Detected::new(
                DefectKind::ReferenceDiff,
                CorruptionLocation::stream(ISO_PVD_MAGIC.start as u64, ISO_PVD_MAGIC.end as u64),
            )
            .with_rule("ISO_PVD_001")
            .with_bytes(actual, Some(expected)),
        );
        return out;
    }

    // TAR block reordering: exactly two 512-byte blocks swapped.
    if format == "TAR" {
        if let Some((a, b)) = tar_block_swap(clean, corrupted) {
            out.push(
                Detected::new(
                    DefectKind::ReferenceDiff,
                    CorruptionLocation::stream((a * 512) as u64, ((b + 1) * 512) as u64),
                )
                .with_rule("TAR_BLOCK_001")
                .with_range(ByteRange::new((a * 512) as u64, ((b + 1) * 512) as u64))
                .with_detail(format!("blocks {a} and {b} swapped")),
            );
            return out;
        }
        // GNU long-name block: a header typeflag changed to 'L'.
        if let Some(off) = tar_gnu_longname(clean, corrupted) {
            out.push(
                Detected::new(
                    DefectKind::ReferenceDiff,
                    CorruptionLocation::stream(off as u64, (off + 512) as u64),
                )
                .with_rule("TAR_GNU_001")
                .with_range(ByteRange::new(off as u64, (off + 512) as u64)),
            );
            return out;
        }
    }

    let first = *diffs.first().unwrap();
    let last = *diffs.last().unwrap();
    let span = last - first + 1;
    let contiguous = diffs.len() == span;

    let actual = corrupted[first..=last.min(first + 63)].to_vec();
    let expected = clean[first..=last.min(first + 63)].to_vec();

    if first == 0
        && contiguous
        && span <= 16
        && magic_rule(format) != "GEN_STRUCT_001"
        && total_bit_diff(&actual, &expected) > 1
    {
        // Leading signature/magic bytes changed (formats with a magic at 0). A
        // single flipped bit in the magic is a recoverable bit flip (the correct
        // value is known), not signature destruction — fall through to the flip
        // branch in that case so recoverability is not under-rated.
        out.push(
            Detected::new(
                DefectKind::ReferenceDiff,
                CorruptionLocation::stream(0, span as u64),
            )
            .with_rule(magic_rule(format))
            .with_bytes(actual, Some(expected))
            .with_range(ByteRange::new(0, span as u64)),
        );
    } else if let Some(rule) = field_resolve(format, clean, corrupted, first) {
        // The changed offset lands in a known structural field (field map).
        out.push(
            Detected::new(
                DefectKind::ReferenceDiff,
                CorruptionLocation::stream(first as u64, (last + 1) as u64),
            )
            .with_rule(rule)
            .with_bytes(actual, Some(expected))
            .with_range(ByteRange::new(first as u64, (last + 1) as u64)),
        );
    } else if (contiguous && diffs.len() >= 8)
        || (diffs.len() >= 16 && diffs.iter().all(|&i| corrupted[i] == 0))
    {
        // A region was overwritten (zeroed or scrambled) ⇒ treated as missing
        // data, matching the corpus zero/random-range rules. The second arm
        // catches scattered zeroing (a media-sector failure whose zeroed bytes
        // interleave with already-zero data, breaking strict contiguity): when
        // every changed byte became zero, it is data loss, not a bit flip.
        out.push(
            Detected::new(
                DefectKind::ReferenceDiff,
                CorruptionLocation::stream(first as u64, (last + 1) as u64),
            )
            .with_rule(missing_rule(format))
            .with_bytes(actual, Some(expected))
            .with_range(ByteRange::new(first as u64, (last + 1) as u64)),
        );
    } else {
        // Otherwise: flipped/altered bits.
        let header = first < 512;
        out.push(
            Detected::new(
                DefectKind::ReferenceDiff,
                CorruptionLocation::stream(first as u64, (last + 1) as u64),
            )
            .with_rule(flip_rule(format, header, diffs.len()))
            .with_bytes(actual, Some(expected))
            .with_range(ByteRange::new(first as u64, (last + 1) as u64)),
        );
    }
    out
}

// ── Field-map-driven structural resolution ──────────────────────────────────

/// If the changed `offset` lands inside a known structural field of `clean`,
/// return that field's rule id. Parses the clean file's structure so the
/// mapping is principled (offset → field → rule), not a guess.
fn field_resolve(
    format: &str,
    clean: &[u8],
    corrupted: &[u8],
    offset: usize,
) -> Option<&'static str> {
    match format {
        "ZIP" => zip_field_at(clean, offset),
        "TAR" => tar_field_at(clean, offset),
        "ISO" => iso_field_at(clean, corrupted, offset),
        _ => None,
    }
}

/// ZIP: map an offset inside a central-directory entry to its field rule.
fn zip_field_at(clean: &[u8], offset: usize) -> Option<&'static str> {
    let eocd = zip_find_eocd(clean)?;
    let cd_offset = u32_le(clean.get(eocd + 16..eocd + 20)?) as usize;
    let mut pos = cd_offset;
    while pos + 46 <= clean.len() && u32_le(&clean[pos..pos + 4]) == 0x0201_4b50 {
        // compressed_size at +20 (4), extra_len at +30 (2).
        if (pos + 20..pos + 24).contains(&offset) {
            return Some("ZIP_SIZE_001");
        }
        if (pos + 30..pos + 32).contains(&offset) {
            return Some("ZIP_EXTRA_001");
        }
        let name_len = u16_le(&clean[pos + 28..pos + 30]) as usize;
        let extra_len = u16_le(&clean[pos + 30..pos + 32]) as usize;
        let comment_len = u16_le(&clean[pos + 32..pos + 34]) as usize;
        pos += 46 + name_len + extra_len + comment_len;
    }
    None
}

/// TAR: map an offset inside a 512-byte header block's size field.
fn tar_field_at(clean: &[u8], offset: usize) -> Option<&'static str> {
    let mut off = 0usize;
    while off + 512 <= clean.len() {
        let block = &clean[off..off + 512];
        if block.iter().all(|&b| b == 0) {
            break;
        }
        // checksum field at +148 (8 bytes) — a UStar checksum corruption.
        if (off + 148..off + 156).contains(&offset) {
            return Some("TAR_UST_001");
        }
        // size field at +124 (12 bytes octal).
        if (off + 124..off + 136).contains(&offset) {
            return Some("TAR_SIZE_001");
        }
        let size = tar_octal(&block[124..136]).unwrap_or(0);
        off += 512 + (size.div_ceil(512) as usize) * 512;
    }
    None
}

/// ISO: map an offset to the supplementary volume descriptor or root directory
/// record region.
fn iso_field_at(_clean: &[u8], corrupted: &[u8], offset: usize) -> Option<&'static str> {
    // SVD magic at sector 17 + 1.
    if (17 * 2048 + 1..17 * 2048 + 6).contains(&offset) {
        return Some("ISO_SVD_001");
    }
    // Root directory record inside the PVD (offset 156, 34 bytes) — flag when a
    // byte there was zeroed (the corpus directory-record corruption).
    let dir = 16 * 2048 + 156;
    if (dir..dir + 34).contains(&offset) && corrupted.get(offset) == Some(&0) {
        return Some("ISO_DIR_001");
    }
    None
}

/// Detect two swapped 512-byte blocks; returns their indices `(a, b)`.
fn tar_block_swap(clean: &[u8], corrupted: &[u8]) -> Option<(usize, usize)> {
    if clean.len() != corrupted.len() {
        return None;
    }
    let nblocks = clean.len() / 512;
    let changed: Vec<usize> = (0..nblocks)
        .filter(|&i| clean[i * 512..(i + 1) * 512] != corrupted[i * 512..(i + 1) * 512])
        .collect();
    if changed.len() == 2 {
        let (a, b) = (changed[0], changed[1]);
        let ca = &clean[a * 512..(a + 1) * 512];
        let cb = &clean[b * 512..(b + 1) * 512];
        let da = &corrupted[a * 512..(a + 1) * 512];
        let db = &corrupted[b * 512..(b + 1) * 512];
        if da == cb && db == ca {
            return Some((a, b));
        }
    }
    None
}

/// Detect a header block whose typeflag (offset +156) became `'L'` (GNU
/// long-name marker). Returns the block offset.
fn tar_gnu_longname(clean: &[u8], corrupted: &[u8]) -> Option<usize> {
    if clean.len() != corrupted.len() {
        return None;
    }
    let mut off = 0usize;
    while off + 512 <= clean.len() {
        if clean[off..off + 512].iter().all(|&b| b == 0) {
            break;
        }
        if corrupted.get(off + 156) == Some(&b'L') && clean.get(off + 156) != Some(&b'L') {
            return Some(off);
        }
        let size = tar_octal(&clean[off + 124..off + 136]).unwrap_or(0);
        off += 512 + (size.div_ceil(512) as usize) * 512;
    }
    None
}

/// Total number of differing bits between two equal-length byte slices.
fn total_bit_diff(a: &[u8], b: &[u8]) -> u32 {
    a.iter().zip(b).map(|(x, y)| (x ^ y).count_ones()).sum()
}

fn u16_le(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}
fn u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}
fn zip_find_eocd(b: &[u8]) -> Option<usize> {
    if b.len() < 22 {
        return None;
    }
    (0..=b.len() - 4)
        .rev()
        .find(|&i| u32_le(&b[i..i + 4]) == 0x0605_4b50)
}
fn tar_octal(field: &[u8]) -> Option<u64> {
    let s: String = field
        .iter()
        .take_while(|&&b| b != 0 && b != b' ')
        .map(|&b| b as char)
        .collect();
    u64::from_str_radix(s.trim(), 8).ok()
}

// ── Rule selection (mirrors the corpus generator) ───────────────────────────

fn tail_trunc_rule(format: &str, pct: f64) -> &'static str {
    match format {
        "ZIP" if pct <= 0.01 => "ZIP_TRUNC_001",
        "ZIP" if pct <= 0.05 => "ZIP_TRUNC_002",
        "ZIP" => "ZIP_TRUNC_003",
        "TAR" if pct <= 0.01 => "TAR_TRUNC_001",
        "TAR" => "TAR_TRUNC_002",
        "ISO" if pct <= 0.05 => "ISO_TRUNC_001",
        "ISO" => "ISO_TRUNC_002",
        _ => "GEN_TRUNC_001",
    }
}

fn head_trunc_rule(format: &str) -> &'static str {
    match format {
        "ZIP" => "ZIP_TRUNC_004",
        "TAR" => "TAR_TRUNC_003",
        "ISO" => "ISO_TRUNC_003",
        _ => "GEN_TRUNC_001",
    }
}

fn flip_rule(format: &str, header: bool, count: usize) -> &'static str {
    // Mirrors the corpus generator's flip_rule: only ZIP/TAR/ISO are
    // special-cased; every other format uses the generic rule.
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

fn magic_rule(format: &str) -> &'static str {
    match format {
        "GZIP" => "GZ_MAGIC_001",
        "BZIP2" => "BZ2_MAGIC_001",
        "XZ" => "XZ_MAGIC_001",
        "ZSTD" => "ZST_MAGIC_001",
        "LZ4" => "LZ4_MAGIC_001",
        "RAR" => "RAR_MAGIC_001",
        "7Z" => "7Z_MAGIC_001",
        "PDF" => "PDF_HDR_001",
        "SQLite" => "SQ_MAGIC_001",
        _ => "GEN_STRUCT_001",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_tail_truncation() {
        let clean = vec![0u8; 1000];
        let corrupted = vec![0u8; 970]; // 3% tail loss
        let d = diff("ZIP", &corrupted, &clean);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].rule_id_override, Some("ZIP_TRUNC_002"));
    }

    #[test]
    fn detects_magic_change() {
        let mut clean = vec![0x11u8; 200];
        clean[0] = 0x1F;
        clean[1] = 0x8B;
        let mut corrupted = clean.clone();
        corrupted[0] = 0;
        corrupted[1] = 0;
        let d = diff("GZIP", &corrupted, &clean);
        assert_eq!(d[0].rule_id_override, Some("GZ_MAGIC_001"));
    }

    #[test]
    fn detects_payload_bitflip() {
        let clean = vec![0xAAu8; 2000];
        let mut corrupted = clean.clone();
        corrupted[1000] ^= 0x01;
        let d = diff("ZIP", &corrupted, &clean);
        assert_eq!(d[0].rule_id_override, Some("ZIP_FLIP_001"));
    }

    #[test]
    fn detects_zeroed_region_as_missing() {
        let clean = vec![0xAAu8; 2000];
        let mut corrupted = clean.clone();
        for b in &mut corrupted[1000..1100] {
            *b = 0;
        }
        let d = diff("ZIP", &corrupted, &clean);
        assert_eq!(d[0].rule_id_override, Some("ZIP_CD_003"));
    }

    #[test]
    fn identical_yields_nothing() {
        let clean = vec![1u8; 100];
        assert!(diff("ZIP", &clean, &clean).is_empty());
    }
}
