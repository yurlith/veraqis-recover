//! Detection and location of raw defects, per format.
//!
//! The detector *finds and locates* anomalies and emits [`Detected`] records.
//! It does not assign category/severity (that is [`super::classifier`]) and it
//! never repairs.

use crate::integrity::crc32::Crc32;
use crate::model::{ArchiveFormat, ByteRange, CorruptionLocation, IntegrityResult};
use crate::reader::{
    BtreeErrorKind, DataSource, IsoParse, IsoReader, SqliteParse, SqliteReader, TarParse,
    TarReader, ZipParse, ZipReader,
};

use super::classifier::{DefectKind, Detected};

/// Build a stream-level location with the two offsets ordered, so a damaged
/// pointer field (e.g. an out-of-bounds ZIP `cd_offset`) can never produce
/// `offset_end < offset_start`.
fn ordered_stream(a: u64, b: u64) -> CorruptionLocation {
    CorruptionLocation::stream(a.min(b), a.max(b))
}

/// Run format-appropriate detection. `verify_embedded_checksums` enables ZIP
/// CRC-32 checking of stored members. `max` caps the number of findings.
pub fn detect(
    source: &DataSource,
    format: ArchiveFormat,
    integrity: &IntegrityResult,
    verify_embedded_checksums: bool,
    max: usize,
) -> (Vec<Detected>, bool) {
    let mut out = Vec::new();

    match format {
        ArchiveFormat::Zip => zip_defects(
            source,
            &ZipReader.parse(source),
            verify_embedded_checksums,
            &mut out,
            max,
        ),
        ArchiveFormat::Tar => tar_defects(source, &TarReader.parse(source), &mut out, max),
        ArchiveFormat::Iso9660 => iso_defects(source, &IsoReader.parse(source), &mut out),
        ArchiveFormat::Gzip => gz_defects(source, &mut out),
        ArchiveFormat::Sqlite => sqlite_defects(source, &SqliteReader.parse(source), &mut out, max),
        ArchiveFormat::SevenZ => sevenz_defects(source, &mut out),
        ArchiveFormat::Rar => rar_defects(source, &mut out),
        ArchiveFormat::Pdf => pdf_stub_defects(source, &mut out),
        ArchiveFormat::Bzip2 => magic_defect(source, &mut out, b"BZh", "BZ2_MAGIC_001"),
        ArchiveFormat::Xz => magic_defect(
            source,
            &mut out,
            &[0xFD, b'7', b'z', b'X', b'Z', 0x00],
            "XZ_MAGIC_001",
        ),
        ArchiveFormat::Zstd => {
            magic_defect(source, &mut out, &[0x28, 0xB5, 0x2F, 0xFD], "ZST_MAGIC_001")
        }
        ArchiveFormat::Lz4 => {
            magic_defect(source, &mut out, &[0x04, 0x22, 0x4D, 0x18], "LZ4_MAGIC_001")
        }
        ArchiveFormat::Raw => {}
    }

    // A manifest mismatch is meaningful for every format: the bytes are not
    // what the reference says they should be.
    if out.len() < max
        && integrity.manifest_present
        && integrity.expected_hash.is_some()
        && !integrity.matches
    {
        let expected = integrity.expected_hash.as_deref().unwrap_or("?");
        out.push(
            Detected::new(
                DefectKind::ManifestHashMismatch,
                CorruptionLocation::stream(0, source.len()),
            )
            .with_bytes(
                integrity.actual_hash.as_bytes().to_vec(),
                Some(expected.as_bytes().to_vec()),
            )
            .with_detail(format!(
                "expected {expected}, computed {}",
                integrity.actual_hash
            )),
        );
    }

    let capped = out.len() >= max;
    out.truncate(max);
    (out, capped)
}

fn magic_defect(source: &DataSource, out: &mut Vec<Detected>, magic: &[u8], rule: &'static str) {
    let actual = source.read_exact_at(0, magic.len()).unwrap_or_default();
    if actual != magic {
        out.push(
            Detected::new(
                DefectKind::ReferenceDiff,
                CorruptionLocation::stream(0, magic.len() as u64),
            )
            .with_rule(rule)
            .with_bytes(actual, Some(magic.to_vec()))
            .with_detail("format signature is damaged or missing"),
        );
    }
}

fn pdf_stub_defects(source: &DataSource, out: &mut Vec<Detected>) {
    magic_defect(source, out, b"%PDF-", "PDF_HDR_001");

    // A conforming PDF terminates with %%EOF, optionally followed by whitespace.
    // Search only a bounded tail; this is structural diagnosis, not object parsing.
    let tail_len = source.len().min(1024) as usize;
    let tail = source
        .read_exact_at(source.len().saturating_sub(tail_len as u64), tail_len)
        .unwrap_or_default();
    if !tail.windows(5).any(|w| w == b"%%EOF") {
        out.push(
            Detected::new(
                DefectKind::ReferenceDiff,
                CorruptionLocation::stream(
                    source.len().saturating_sub(tail_len as u64),
                    source.len(),
                ),
            )
            .with_rule("PDF_EOF_001")
            .with_bytes(
                tail.get(tail.len().saturating_sub(5)..)
                    .unwrap_or(&[])
                    .to_vec(),
                Some(b"%%EOF".to_vec()),
            )
            .with_detail("PDF end-of-file marker is missing"),
        );
    }
}

fn zip_defects(
    source: &DataSource,
    parse: &ZipParse,
    verify_crc: bool,
    out: &mut Vec<Detected>,
    max: usize,
) {
    let Some(eocd) = parse.eocd_offset else {
        out.push(
            Detected::new(
                DefectKind::ZipMissingEocd,
                CorruptionLocation::stream(0, source.len()),
            )
            .with_bytes(Vec::new(), Some(vec![0x50, 0x4B, 0x05, 0x06])),
        );
        return;
    };

    if !parse.cd_present {
        let len = source.len();
        let cd_off = parse.cd_offset as u64;
        if cd_off >= len {
            // EOCD points past EOF — the directory is unreachable.
            let actual = source.read_exact_at(eocd + 16, 4).unwrap_or_default();
            out.push(
                Detected::new(DefectKind::ZipEocdCdOffsetOob, ordered_stream(cd_off, eocd))
                    .with_bytes(actual, None)
                    .with_confidence(crate::corruption::confidence::offset_out_of_bounds(
                        cd_off, len,
                    ))
                    .with_detail(format!("cd_offset {cd_off} >= file size {len}")),
            );
        } else {
            // In-bounds but no central-directory signature ⇒ zeroed/removed.
            let actual = source.read_exact_at(cd_off, 4).unwrap_or_default();
            out.push(
                Detected::new(
                    DefectKind::ZipCentralDirectoryMissing,
                    ordered_stream(cd_off, eocd),
                )
                .with_bytes(actual, Some(vec![0x50, 0x4B, 0x01, 0x02]))
                .with_detail(format!("central directory offset {cd_off}")),
            );
        }
    }

    if parse.cd_present && parse.declared_entries as usize != parse.entries.len() {
        out.push(
            Detected::new(
                DefectKind::ZipEntryCountMismatch,
                ordered_stream(parse.cd_offset as u64, eocd),
            )
            .with_detail(format!(
                "EOCD declares {}, directory has {}",
                parse.declared_entries,
                parse.entries.len()
            )),
        );
    }

    if !parse.local_headers_ok {
        let off = parse.entries.first().map(|e| e.offset).unwrap_or(0);
        let actual = source.read_exact_at(off, 4).unwrap_or_default();
        out.push(
            Detected::new(
                DefectKind::ZipLocalHeaderMissing,
                CorruptionLocation::stream(off, off + 4),
            )
            .with_bytes(actual, Some(vec![0x50, 0x4B, 0x03, 0x04])),
        );
    }

    if verify_crc {
        for (entry, &method) in parse.entries.iter().zip(parse.methods.iter()) {
            if out.len() >= max {
                break;
            }

            // Compare LFH compressed_size (ground truth) against the CD value.
            // When these disagree the CD field is corrupted (ZIP_SIZE_001).
            // This check runs for every method and supersedes the CRC check,
            // which would compute junk with the wrong byte count.
            let lfh_hdr = source.read_exact_at(entry.offset, 22).ok();
            let lfh_comp = lfh_hdr
                .as_ref()
                .filter(|h| h.len() >= 22)
                .map(|h| u32::from_le_bytes([h[18], h[19], h[20], h[21]]) as u64);
            if let Some(lfh_size) = lfh_comp {
                if lfh_size != entry.compressed_size {
                    out.push(
                        Detected::new(
                            DefectKind::ZipSizeMismatch,
                            CorruptionLocation {
                                file_path: Some(entry.path.clone()),
                                offset_start: entry.offset + 18,
                                offset_end: entry.offset + 22,
                            },
                        )
                        .with_bytes(
                            (entry.compressed_size as u32).to_le_bytes().to_vec(),
                            Some(lfh_size.to_le_bytes()[..4].to_vec()),
                        )
                        .with_detail(format!(
                            "{}: LFH compressed_size {lfh_size}, CD says {}",
                            entry.path.display(),
                            entry.compressed_size
                        )),
                    );
                    continue; // CRC check with wrong size would be meaningless
                }
            }

            // CRC-32 can only be checked without decompression for *stored*
            // (method 0) members; verifying compressed members would require
            // an inflater, which V1 omits.
            if method != 0 {
                continue;
            }
            let Some(stored_crc) = entry.stored_crc32 else {
                continue;
            };
            if let Some((data_off, computed)) =
                stored_member_crc(source, entry.offset, entry.compressed_size)
            {
                if computed != stored_crc {
                    out.push(
                        Detected::new(
                            DefectKind::ZipCrcMismatch,
                            CorruptionLocation {
                                file_path: Some(entry.path.clone()),
                                offset_start: data_off,
                                offset_end: data_off + entry.compressed_size,
                            },
                        )
                        .with_range(ByteRange::new(data_off, data_off + entry.compressed_size))
                        .with_bytes(
                            computed.to_le_bytes().to_vec(),
                            Some(stored_crc.to_le_bytes().to_vec()),
                        )
                        .with_detail(format!(
                            "{}: stored {stored_crc:08x}, computed {computed:08x}",
                            entry.path.display()
                        )),
                    );
                }
            }
        }
    }
}

/// Compute the CRC-32 of a stored member's data, returning `(data_offset, crc)`.
fn stored_member_crc(source: &DataSource, lfh_offset: u64, size: u64) -> Option<(u64, u32)> {
    // Local file header: name length at +26, extra length at +28.
    let header = source.read_exact_at(lfh_offset, 30).ok()?;
    let name_len = u16::from_le_bytes([header[26], header[27]]) as u64;
    let extra_len = u16::from_le_bytes([header[28], header[29]]) as u64;
    let data_off = lfh_offset + 30 + name_len + extra_len;

    let mut crc = Crc32::new();
    let mut remaining = size;
    let mut cursor = data_off;
    let mut buf = [0u8; 64 * 1024];
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        let n = source.read_at(cursor, &mut buf[..want]).ok()?;
        if n == 0 {
            return None; // truncated; caller's structural checks cover this
        }
        crc.update(&buf[..n]);
        cursor += n as u64;
        remaining -= n as u64;
    }
    Some((data_off, crc.finalize()))
}

fn tar_defects(source: &DataSource, parse: &TarParse, out: &mut Vec<Detected>, max: usize) {
    for (offset, name) in &parse.checksum_failures {
        if out.len() >= max {
            break;
        }
        let actual = source.read_exact_at(offset + 148, 8).unwrap_or_default();
        out.push(
            Detected::new(
                DefectKind::TarHeaderChecksumBad,
                CorruptionLocation::stream(*offset, offset + 512),
            )
            .with_bytes(actual, None)
            .with_detail(name.clone()),
        );
    }

    if parse.truncated {
        out.push(Detected::new(
            DefectKind::TarTruncated,
            CorruptionLocation::stream(0, 0),
        ));
    } else if !parse.zero_terminator_present {
        out.push(Detected::new(
            DefectKind::TarMissingTerminator,
            CorruptionLocation::stream(0, 0),
        ));
    }
}

fn iso_defects(source: &DataSource, parse: &IsoParse, out: &mut Vec<Detected>) {
    if !parse.pvd_present {
        // "CD001" lives at offset 32769 (PVD at sector 16 + 1).
        let actual = source.read_exact_at(32769, 5).unwrap_or_default();
        out.push(
            Detected::new(
                DefectKind::IsoMissingPvd,
                CorruptionLocation::stream(0, source.len()),
            )
            .with_bytes(actual, Some(b"CD001".to_vec())),
        );
        return;
    }
    if !parse.path_table_in_bounds {
        let actual = source.read_exact_at(16 * 2048 + 140, 4).unwrap_or_default();
        out.push(
            Detected::new(
                DefectKind::IsoPathTableOutOfBounds,
                CorruptionLocation::stream(0, source.len()),
            )
            .with_bytes(actual, None)
            .with_confidence(crate::corruption::confidence::offset_out_of_bounds(
                parse.path_table_lba as u64 * 2048,
                source.len(),
            ))
            .with_detail(format!("path-table LBA {}", parse.path_table_lba)),
        );
    }
}

/// GZIP format structure:
///   [0..2]   magic 1F 8B
///   [2]      compression method (08 = DEFLATE)
///   [3]      flags
///   [4..8]   mtime (u32 LE)
///   [8]      extra flags
///   [9]      OS
///   ... optional header extensions (FEXTRA, FNAME, FCOMMENT, FHCRC) ...
///   ... DEFLATE stream ...
///   [-8..-4] CRC32 of decompressed data (u32 LE)
///   [-4..]   ISIZE = decompressed length mod 2^32 (u32 LE)
///
/// Minimum valid size: 18 bytes (10 header + 2 empty DEFLATE + 4 CRC32 + 4 ISIZE ≥ actual 20).
const GZ_MIN_SIZE: u64 = 18;
/// Cap decompression so a corrupted size field can't allocate unbounded RAM.
const GZ_DECOMP_CAP: usize = 64 * 1024 * 1024;

/// 7-Zip signature-header checks (P0): the 6-byte signature and the Start Header
/// CRC-32 (stored LE at `[8,12)`, over bytes `[12,32)`). Full packed-header
/// parsing is a later phase; this matches the signature-level field map.
fn sevenz_defects(source: &DataSource, out: &mut Vec<Detected>) {
    const SIG: [u8; 6] = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
    let want = (source.len() as usize).min(32);
    let head = source.read_exact_at(0, want).unwrap_or_default();
    let sig = head.get(..6).unwrap_or(&[]);
    if sig != SIG {
        out.push(
            Detected::new(DefectKind::SevenZMagicBad, CorruptionLocation::stream(0, 6))
                .with_bytes(sig.to_vec(), Some(SIG.to_vec()))
                .with_detail("7z signature should be 37 7A BC AF 27 1C"),
        );
        return;
    }
    if head.len() >= 32 {
        let stored = u32::from_le_bytes([head[8], head[9], head[10], head[11]]);
        let computed = crate::integrity::crc32::crc32(&head[12..32]);
        if stored != computed {
            out.push(
                Detected::new(
                    DefectKind::SevenZStartHeaderCrcBad,
                    CorruptionLocation::stream(8, 12),
                )
                .with_bytes(head[8..12].to_vec(), Some(computed.to_le_bytes().to_vec()))
                .with_detail(format!(
                    "7z Start Header CRC32 0x{stored:08X}; computed 0x{computed:08X}"
                )),
            );
        } else {
            // The Start-Header CRC validates → `NextHeaderOffset`/`Size` are the
            // *true original* values. If the end header they point to lies past
            // EOF, the file was truncated (7z has no per-folder local headers, so
            // the tail end header is the only structure map). Zero-false: the
            // pointer is CRC-proven, so "points past EOF" ⇒ bytes are genuinely
            // missing.
            let next_off = u64::from_le_bytes([
                head[12], head[13], head[14], head[15], head[16], head[17], head[18], head[19],
            ]);
            let next_size = u64::from_le_bytes([
                head[20], head[21], head[22], head[23], head[24], head[25], head[26], head[27],
            ]);
            let end = 32u64
                .checked_add(next_off)
                .and_then(|s| s.checked_add(next_size));
            let truncated = end.map(|e| e > source.len()).unwrap_or(true);
            if truncated && next_size > 0 {
                out.push(
                    Detected::new(
                        DefectKind::SevenZEndHeaderOob,
                        CorruptionLocation::stream(12, 28),
                    )
                    .with_detail(format!(
                        "7z end header at offset {} size {} exceeds file size {}",
                        32 + next_off,
                        next_size,
                        source.len()
                    )),
                );
            }
        }
    }
}

/// RAR signature check (P0): RAR4 `Rar!\x1A\x07\x00` or RAR5 `Rar!\x1A\x07\x01\x00`.
/// Block-level CRC validation is a later phase.
fn rar_defects(source: &DataSource, out: &mut Vec<Detected>) {
    const PREFIX: [u8; 6] = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07];
    let want = (source.len() as usize).min(8);
    let head = source.read_exact_at(0, want).unwrap_or_default();
    let ok = head.len() >= 7
        && head[..6] == PREFIX
        && (head[6] == 0x00 || (head[6] == 0x01 && head.len() >= 8 && head[7] == 0x00));
    if !ok {
        out.push(
            Detected::new(DefectKind::RarMagicBad, CorruptionLocation::stream(0, 7))
                .with_bytes(
                    head.get(..head.len().min(8)).unwrap_or(&[]).to_vec(),
                    Some(vec![0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00]),
                )
                .with_detail(
                    "RAR signature should be 52 61 72 21 1A 07 00 (RAR4) or ..01 00 (RAR5)",
                ),
        );
    }
}

fn gz_defects(source: &DataSource, out: &mut Vec<Detected>) {
    use std::io::Read;

    let len = source.len();

    if len < GZ_MIN_SIZE {
        out.push(
            Detected::new(DefectKind::GzTruncated, CorruptionLocation::stream(0, len))
                .with_bytes(
                    source
                        .read_exact_at(0, len.min(10) as usize)
                        .unwrap_or_default(),
                    None,
                )
                .with_detail(format!(
                    "file is only {len} bytes; minimum GZIP is {GZ_MIN_SIZE}"
                )),
        );
        return;
    }

    let raw_bytes = match source.stream() {
        Ok(mut r) => {
            let mut b = Vec::new();
            let _ = r.read_to_end(&mut b);
            b
        }
        Err(_) => return,
    };

    let head = &raw_bytes[..raw_bytes.len().min(10)];

    // Magic bytes check.
    let magic_ok = head.len() >= 2 && head[0] == 0x1F && head[1] == 0x8B;
    if !magic_ok {
        out.push(
            Detected::new(DefectKind::GzMagicBad, CorruptionLocation::stream(0, 2))
                .with_bytes(
                    head.get(0..2).unwrap_or(&[]).to_vec(),
                    Some(vec![0x1F, 0x8B]),
                )
                .with_detail("magic bytes should be 1F 8B"),
        );
    }

    // Compression method check.
    if head.len() >= 3 && head[2] != 0x08 {
        out.push(
            Detected::new(
                DefectKind::GzCompressionMethodBad,
                CorruptionLocation::stream(2, 3),
            )
            .with_bytes(vec![head[2]], Some(vec![0x08]))
            .with_detail(format!(
                "CM byte is 0x{:02X}; only DEFLATE (0x08) is supported",
                head[2]
            )),
        );
        return;
    }

    // Locate the DEFLATE body by skipping the variable-length header extensions.
    let body_start = gz_body_start(&raw_bytes);
    let trailer_start = raw_bytes.len().saturating_sub(8);

    if body_start >= trailer_start {
        if out.is_empty() {
            out.push(
                Detected::new(
                    DefectKind::GzTruncated,
                    CorruptionLocation::stream(body_start as u64, len),
                )
                .with_detail("DEFLATE body region is empty or overlaps trailer"),
            );
        }
        return;
    }

    // Read the stored trailer values (last 8 bytes).
    let stored_crc32 = u32::from_le_bytes(
        raw_bytes[trailer_start..trailer_start + 4]
            .try_into()
            .unwrap_or([0; 4]),
    );
    let stored_isize = u32::from_le_bytes(
        raw_bytes[trailer_start + 4..trailer_start + 8]
            .try_into()
            .unwrap_or([0; 4]),
    );

    // Decompress using DeflateDecoder directly on the body — it does NOT check the
    // GZIP trailer, so we get the decompressed bytes regardless of trailer errors.
    // This is the correct approach: MultiGzDecoder would fail *after* successful
    // decompression if the trailer is wrong, masking GZ_ICRC_001 / GZ_ISIZE_001.
    let deflate_body = &raw_bytes[body_start..trailer_start];
    let mut decoder = flate2::read::DeflateDecoder::new(deflate_body);
    let mut decompressed = Vec::new();
    let fully_decompressed = decoder.read_to_end(&mut decompressed).is_ok();
    let decompressed = &decompressed[..decompressed.len().min(GZ_DECOMP_CAP)];

    if !fully_decompressed {
        // Partial decompression = the body is truncated or internally corrupted.
        if out.is_empty() {
            out.push(
                Detected::new(
                    DefectKind::GzTruncated,
                    CorruptionLocation::stream(body_start as u64, len),
                )
                .with_detail(format!(
                    "{} bytes decompressed before stream error",
                    decompressed.len()
                )),
            );
        }
        return;
    }

    // Trailer checks — only run when decompression fully succeeded.
    let actual_crc = crate::integrity::crc32::crc32(decompressed);
    if actual_crc != stored_crc32 {
        out.push(
            Detected::new(
                DefectKind::GzCrcBad,
                CorruptionLocation::stream(len - 8, len - 4),
            )
            .with_bytes(
                stored_crc32.to_le_bytes().to_vec(),
                Some(actual_crc.to_le_bytes().to_vec()),
            )
            .with_detail(format!(
                "trailer CRC32 0x{stored_crc32:08X}; computed 0x{actual_crc:08X}"
            )),
        );
    }

    let actual_isize = decompressed.len() as u32;
    if actual_isize != stored_isize {
        out.push(
            Detected::new(
                DefectKind::GzIsizeBad,
                CorruptionLocation::stream(len - 4, len),
            )
            .with_bytes(
                stored_isize.to_le_bytes().to_vec(),
                Some(actual_isize.to_le_bytes().to_vec()),
            )
            .with_detail(format!(
                "trailer ISIZE {stored_isize}; decompressed size {}",
                decompressed.len()
            )),
        );
    }
}

fn sqlite_defects(_source: &DataSource, p: &SqliteParse, out: &mut Vec<Detected>, max: usize) {
    if out.len() >= max {
        return;
    }

    // ── Header magic ─────────────────────────────────────────────────────────
    if !p.magic_ok {
        out.push(
            Detected::new(DefectKind::SqMagicBad, CorruptionLocation::stream(0, 16))
                .with_bytes(Vec::new(), Some(b"SQLite format 3\0".to_vec()))
                .with_detail("SQLite header magic mismatch"),
        );
        // Without valid magic, further structural checks are meaningless.
        return;
    }

    // ── Page size ────────────────────────────────────────────────────────────
    if !p.page_size_valid {
        out.push(
            Detected::new(
                DefectKind::SqPageSizeBad,
                CorruptionLocation::stream(16, 18),
            )
            .with_bytes(p.page_size_raw.to_be_bytes().to_vec(), None)
            .with_detail(format!(
                "page_size {} is not a power of two in [512, 65536]",
                p.page_size
            )),
        );
        return; // Page walks require a valid page size.
    }

    if out.len() < max && !p.page_count_matches && p.declared_pages > 0 {
        if let Some(actual) = p.actual_pages {
            out.push(
                Detected::new(
                    DefectKind::SqPageSizeMismatch,
                    CorruptionLocation::stream(28, 32),
                )
                .with_bytes(p.declared_pages.to_be_bytes().to_vec(), None)
                .with_detail(format!(
                    "declared {} pages but file holds {} ({} bytes, page_size {})",
                    p.declared_pages,
                    actual,
                    _source.len(),
                    p.page_size
                )),
            );
        }
    }

    // ── Truncation ───────────────────────────────────────────────────────────
    if out.len() < max && p.truncated_before_page2 {
        out.push(
            Detected::new(
                DefectKind::SqTruncatedBeforePage2,
                CorruptionLocation::stream(0, _source.len()),
            )
            .with_detail(format!(
                "file {} bytes; need at least {} for two pages",
                _source.len(),
                p.page_size * 2
            )),
        );
        return;
    }

    if out.len() < max && !p.ends_on_page_boundary && !p.truncated_before_page2 {
        out.push(
            Detected::new(
                DefectKind::SqTruncatedMidPage,
                CorruptionLocation::stream(0, _source.len()),
            )
            .with_detail(format!(
                "file {} bytes is not a multiple of page_size {}",
                _source.len(),
                p.page_size
            )),
        );
    }

    // ── Freelist ─────────────────────────────────────────────────────────────
    if out.len() < max && !p.freelist_trunk_valid {
        let ap = p.actual_pages.unwrap_or(0);
        out.push(
            Detected::new(
                DefectKind::SqFreelistTrunkBad,
                CorruptionLocation::stream(32, 36),
            )
            .with_bytes(p.freelist_trunk.to_be_bytes().to_vec(), None)
            .with_detail(format!(
                "freelist trunk page {} > actual page count {}",
                p.freelist_trunk, ap
            )),
        );
    }

    if out.len() < max && !p.freelist_count_valid {
        let ap = p.actual_pages.unwrap_or(0);
        out.push(
            Detected::new(
                DefectKind::SqFreelistCountBad,
                CorruptionLocation::stream(36, 40),
            )
            .with_bytes(p.freelist_count.to_be_bytes().to_vec(), None)
            .with_detail(format!(
                "freelist count {} > actual page count {}",
                p.freelist_count, ap
            )),
        );
    }

    // ── File-change counter (rollback-journal mode only) ──────────────────────
    // In WAL mode (write_version==2) the counters are maintained differently;
    // skip the check to avoid false positives on valid WAL-mode databases.
    if out.len() < max && p.write_version == 1 && p.file_change_counter != p.version_valid_for {
        out.push(
            Detected::new(
                DefectKind::SqFileChangeCounter,
                CorruptionLocation::stream(24, 28),
            )
            .with_bytes(
                p.version_valid_for.to_be_bytes().to_vec(),
                Some(p.file_change_counter.to_be_bytes().to_vec()),
            )
            .with_detail(format!(
                "file_change_counter {} ≠ version_valid_for {}",
                p.file_change_counter, p.version_valid_for
            )),
        );
    }

    // ── B-tree page errors ───────────────────────────────────────────────────
    for e in &p.btree_errors {
        if out.len() >= max {
            break;
        }
        let (kind, detail) = match &e.kind {
            BtreeErrorKind::InvalidPageType(t) => (
                DefectKind::SqBtreePageTypeBad,
                format!(
                    "page {}: type byte 0x{:02X} not in {{2,5,10,13}}",
                    e.page_num, t
                ),
            ),
            BtreeErrorKind::CellCountExceedsCapacity { count, page_size } => (
                DefectKind::SqBtreeCellCountBad,
                format!(
                    "page {}: cell_count {} exceeds capacity for page_size {}",
                    e.page_num, count, page_size
                ),
            ),
            BtreeErrorKind::CellPtrOutOfBounds { ptr, page_size } => (
                DefectKind::SqBtreeCellPtrBad,
                format!(
                    "page {}: cell_ptr 0x{:04X} >= page_size {}",
                    e.page_num, ptr, page_size
                ),
            ),
        };
        out.push(
            Detected::new(
                kind,
                CorruptionLocation::stream(e.page_offset, e.page_offset + p.page_size as u64),
            )
            .with_detail(detail),
        );
    }

    // ── WAL ──────────────────────────────────────────────────────────────────
    if out.len() < max && p.wal_present && !p.wal_magic_ok {
        out.push(
            Detected::new(DefectKind::SqWalMagicBad, CorruptionLocation::stream(0, 4))
                .with_detail("WAL file magic is not 0x377F0682 or 0x377F0683"),
        );
    }

    if out.len() < max && p.wal_present && p.wal_magic_ok && !p.wal_salt_matches {
        out.push(
            Detected::new(
                DefectKind::SqWalSaltMismatch,
                CorruptionLocation::stream(16, 20),
            )
            .with_detail("WAL salt-1 does not match database version_valid_for"),
        );
    }
}

/// Skip past the optional GZIP header extensions (FEXTRA, FNAME, FCOMMENT, FHCRC)
/// and return the index of the first byte of the DEFLATE body.
fn gz_body_start(data: &[u8]) -> usize {
    if data.len() < 10 {
        return data.len();
    }
    let flags = data[3];
    let mut pos = 10usize;
    if flags & 0x04 != 0 {
        if pos + 2 > data.len() {
            return data.len();
        }
        let xlen = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2 + xlen;
    }
    if flags & 0x08 != 0 {
        while pos < data.len() && data[pos] != 0 {
            pos += 1;
        }
        pos += 1;
    }
    if flags & 0x10 != 0 {
        while pos < data.len() && data[pos] != 0 {
            pos += 1;
        }
        pos += 1;
    }
    if flags & 0x02 != 0 {
        pos += 2;
    }
    pos.min(data.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::HashType;

    fn clean_integrity() -> IntegrityResult {
        IntegrityResult::without_manifest(HashType::Sha256, "x".into())
    }

    #[test]
    fn raw_format_reports_no_structural_defects() {
        let src = DataSource::from_bytes("r", vec![1, 2, 3]);
        let (d, capped) = detect(&src, ArchiveFormat::Raw, &clean_integrity(), true, 100);
        assert!(d.is_empty());
        assert!(!capped);
    }

    #[test]
    fn zip_without_eocd_flagged_missing() {
        let src = DataSource::from_bytes("z.zip", vec![0u8; 200]);
        let (d, _) = detect(&src, ArchiveFormat::Zip, &clean_integrity(), true, 100);
        assert!(d.iter().any(|x| x.kind == DefectKind::ZipMissingEocd));
    }

    #[test]
    fn manifest_mismatch_emits_finding() {
        let mut integ = clean_integrity();
        integ.manifest_present = true;
        integ.expected_hash = Some("aa".into());
        integ.actual_hash = "bb".into();
        integ.matches = false;
        let src = DataSource::from_bytes("r", vec![1, 2, 3]);
        let (d, _) = detect(&src, ArchiveFormat::Raw, &integ, true, 100);
        assert!(d.iter().any(|x| x.kind == DefectKind::ManifestHashMismatch));
    }

    /// A 32-byte 7z signature header with a correct Start Header CRC over an
    /// all-zero start header (NextHeaderOffset/Size/CRC = 0).
    fn valid_7z_header() -> Vec<u8> {
        let mut v = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04]; // sig + v0.4
        let start_header = [0u8; 20];
        v.extend_from_slice(&crate::integrity::crc32::crc32(&start_header).to_le_bytes());
        v.extend_from_slice(&start_header);
        v
    }

    #[test]
    fn clean_7z_header_has_no_defects() {
        let src = DataSource::from_bytes("a.7z", valid_7z_header());
        let (d, _) = detect(&src, ArchiveFormat::SevenZ, &clean_integrity(), true, 100);
        assert!(d.is_empty(), "{d:?}");
    }

    #[test]
    fn sevenz_bad_signature_flags_magic() {
        let mut v = valid_7z_header();
        v[2] ^= 0xFF; // corrupt the signature
        let src = DataSource::from_bytes("a.7z", v);
        let (d, _) = detect(&src, ArchiveFormat::SevenZ, &clean_integrity(), true, 100);
        assert!(d.iter().any(|x| x.kind == DefectKind::SevenZMagicBad));
    }

    #[test]
    fn sevenz_bad_start_header_crc_flagged() {
        let mut v = valid_7z_header();
        v[12] ^= 0x01; // mutate a start-header byte → stored CRC no longer matches
        let src = DataSource::from_bytes("a.7z", v);
        let (d, _) = detect(&src, ArchiveFormat::SevenZ, &clean_integrity(), true, 100);
        assert!(d
            .iter()
            .any(|x| x.kind == DefectKind::SevenZStartHeaderCrcBad));
    }

    #[test]
    fn clean_rar5_signature_has_no_defects() {
        let mut v = vec![0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00];
        v.extend_from_slice(&[0u8; 32]); // arbitrary trailing bytes
        let src = DataSource::from_bytes("a.rar", v);
        let (d, _) = detect(&src, ArchiveFormat::Rar, &clean_integrity(), true, 100);
        assert!(d.is_empty(), "{d:?}");
    }

    #[test]
    fn rar_bad_signature_flags_magic() {
        let src = DataSource::from_bytes("a.rar", vec![0u8; 64]); // no RAR signature
        let (d, _) = detect(&src, ArchiveFormat::Rar, &clean_integrity(), true, 100);
        assert!(d.iter().any(|x| x.kind == DefectKind::RarMagicBad));
    }

    #[test]
    fn sevenz_truncated_end_header_flagged() {
        // CRC-valid start header says the end header is at 32+1000 (size 50), but
        // the file is only 40 bytes → truncated → SevenZEndHeaderOob.
        let (next_off, next_size, next_crc): (u64, u64, u32) = (1000, 50, 0);
        let mut start = Vec::new();
        start.extend_from_slice(&next_off.to_le_bytes());
        start.extend_from_slice(&next_size.to_le_bytes());
        start.extend_from_slice(&next_crc.to_le_bytes());
        let sh_crc = crate::integrity::crc32::crc32(&start);
        let mut v = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];
        v.extend_from_slice(&sh_crc.to_le_bytes());
        v.extend_from_slice(&start); // → 32 bytes
        v.extend_from_slice(&[0u8; 8]); // total 40 ≪ 32+1000+50
        let src = DataSource::from_bytes("t.7z", v);
        let (d, _) = detect(&src, ArchiveFormat::SevenZ, &clean_integrity(), true, 100);
        assert!(d.iter().any(|x| x.kind == DefectKind::SevenZEndHeaderOob));
    }

    /// Regression: an out-of-bounds ZIP `cd_offset` (cd_offset > eocd) must not
    /// panic via `offset_end < offset_start`. Surfaced by the Phase 1 corpus.
    #[test]
    fn oob_cd_offset_does_not_panic() {
        let mut z = Vec::new();
        z.extend_from_slice(&0x0605_4b50u32.to_le_bytes()); // EOCD sig
        z.extend_from_slice(&0u16.to_le_bytes()); // disk
        z.extend_from_slice(&0u16.to_le_bytes()); // disk w/ cd
        z.extend_from_slice(&1u16.to_le_bytes()); // entries this disk (claim 1)
        z.extend_from_slice(&1u16.to_le_bytes()); // total entries
        z.extend_from_slice(&0u32.to_le_bytes()); // cd size
        z.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // cd offset (OOB)
        z.extend_from_slice(&0u16.to_le_bytes()); // comment len
        let src = DataSource::from_bytes("oob.zip", z);
        // Must complete without panicking and flag the bad directory.
        let (d, _) = detect(&src, ArchiveFormat::Zip, &clean_integrity(), true, 100);
        assert!(d
            .iter()
            .all(|x| x.location.offset_end >= x.location.offset_start));
        assert!(!d.is_empty());
    }
}
