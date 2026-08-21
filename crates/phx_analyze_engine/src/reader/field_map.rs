//! Format structure field maps (Phase 2, Step 2.2).
//!
//! Declarative tables describing the on-disk fields of each format: where a
//! field lives, how long it is, its expected value (for signatures) and valid
//! numeric range. The corruption detector and evidence layer consult these to
//! describe findings precisely. ZIP/TAR/ISO/GZIP are populated; PDF/SQLite are
//! stubs pending their parsers.

/// How to locate a field within the stream or the current entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OffsetRule {
    /// Absolute offset from the start of the file.
    Fixed(u64),
    /// Offset measured back from the end of the file.
    FromEnd(u64),
    /// Immediately after the named field.
    AfterField(&'static str),
    /// Offset relative to the current entry's start.
    EntryRelative(u64),
    /// Determined at parse time (dynamic).
    Computed,
}

/// Field length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldLength {
    Fixed(usize),
    /// Length read from another field.
    Variable,
}

/// A single structural field definition.
#[derive(Debug, Clone, Copy)]
pub struct FieldDef {
    pub name: &'static str,
    pub description: &'static str,
    pub offset_rule: OffsetRule,
    pub length: FieldLength,
    pub expected_value: Option<&'static [u8]>,
    pub valid_range: Option<(u64, u64)>,
}

const fn f(
    name: &'static str,
    description: &'static str,
    offset_rule: OffsetRule,
    length: FieldLength,
    expected_value: Option<&'static [u8]>,
    valid_range: Option<(u64, u64)>,
) -> FieldDef {
    FieldDef {
        name,
        description,
        offset_rule,
        length,
        expected_value,
        valid_range,
    }
}

use FieldLength::Fixed as L;
use OffsetRule::{Computed, EntryRelative as ER, Fixed as At, FromEnd};

/// ZIP field map (complete, per the Step 2.2 table).
pub static ZIP_FIELDS: &[FieldDef] = &[
    f(
        "LocalFileHeader.signature",
        "Local file header signature",
        At(0),
        L(4),
        Some(&[0x50, 0x4B, 0x03, 0x04]),
        None,
    ),
    f(
        "LocalFileHeader.version_needed",
        "Version needed to extract",
        ER(4),
        L(2),
        None,
        Some((10, 63)),
    ),
    f(
        "LocalFileHeader.flags",
        "General purpose bit flag",
        ER(6),
        L(2),
        None,
        Some((0x0000, 0x083F)),
    ),
    f(
        "LocalFileHeader.compression",
        "Compression method",
        ER(8),
        L(2),
        None,
        Some((0, 20)),
    ),
    f(
        "LocalFileHeader.crc32",
        "CRC-32 of uncompressed data",
        ER(14),
        L(4),
        None,
        None,
    ),
    f(
        "LocalFileHeader.compressed_size",
        "Compressed size",
        ER(18),
        L(4),
        None,
        None,
    ),
    f(
        "LocalFileHeader.uncompressed_size",
        "Uncompressed size",
        ER(22),
        L(4),
        None,
        None,
    ),
    f(
        "LocalFileHeader.filename_len",
        "File name length",
        ER(26),
        L(2),
        None,
        Some((1, 65535)),
    ),
    f(
        "LocalFileHeader.extra_len",
        "Extra field length",
        ER(28),
        L(2),
        None,
        Some((0, 65535)),
    ),
    f(
        "CentralDirHeader.signature",
        "Central directory file header signature",
        Computed,
        L(4),
        Some(&[0x50, 0x4B, 0x01, 0x02]),
        None,
    ),
    f(
        "CentralDirHeader.disk_number_start",
        "Disk number start",
        ER(34),
        L(2),
        None,
        Some((0, 0)),
    ),
    f(
        "EOCD.signature",
        "End of central directory signature",
        FromEnd(22),
        L(4),
        Some(&[0x50, 0x4B, 0x05, 0x06]),
        None,
    ),
    f(
        "EOCD.disk_number",
        "Number of this disk",
        FromEnd(18),
        L(2),
        None,
        Some((0, 0)),
    ),
    f(
        "EOCD.cd_start_disk",
        "Disk where central directory starts",
        FromEnd(16),
        L(2),
        None,
        Some((0, 0)),
    ),
    f(
        "EOCD.cd_entry_count_disk",
        "CD entries on this disk",
        FromEnd(14),
        L(2),
        None,
        None,
    ),
    f(
        "EOCD.cd_entry_count_total",
        "Total CD entries",
        FromEnd(12),
        L(2),
        None,
        Some((1, 65535)),
    ),
    f(
        "EOCD.cd_size",
        "Size of central directory",
        FromEnd(10),
        L(4),
        None,
        None,
    ),
    f(
        "EOCD.cd_offset",
        "Offset of central directory",
        FromEnd(6),
        L(4),
        None,
        None,
    ),
    f(
        "EOCD.comment_len",
        "Comment length",
        FromEnd(2),
        L(2),
        None,
        Some((0, 65535)),
    ),
    f(
        "ZIP64_EOCD_Locator.signature",
        "ZIP64 EOCD locator signature",
        Computed,
        L(4),
        Some(&[0x50, 0x4B, 0x06, 0x07]),
        None,
    ),
    f(
        "ZIP64_EOCD_Locator.eocd64_offset",
        "Offset of ZIP64 EOCD",
        Computed,
        L(8),
        None,
        None,
    ),
];

/// TAR (UStar) field map.
pub static TAR_FIELDS: &[FieldDef] = &[
    f("UStarHeader.name", "File name", ER(0), L(100), None, None),
    f(
        "UStarHeader.size",
        "File size (octal)",
        ER(124),
        L(12),
        None,
        None,
    ),
    f(
        "UStarHeader.checksum",
        "Header checksum (octal)",
        ER(148),
        L(8),
        None,
        None,
    ),
    f(
        "UStarHeader.typeflag",
        "Type flag",
        ER(156),
        L(1),
        None,
        None,
    ),
    f(
        "UStarHeader.magic",
        "UStar magic",
        ER(257),
        L(6),
        Some(b"ustar\0"),
        None,
    ),
];

/// ISO 9660 field map (Primary Volume Descriptor at sector 16).
pub static ISO_FIELDS: &[FieldDef] = &[
    f(
        "PrimaryVolumeDescriptor.type",
        "Volume descriptor type",
        At(32768),
        L(1),
        Some(&[1]),
        None,
    ),
    f(
        "PrimaryVolumeDescriptor.magic",
        "Standard identifier",
        At(32769),
        L(5),
        Some(b"CD001"),
        None,
    ),
    f(
        "PrimaryVolumeDescriptor.volume_space",
        "Volume space size (LE)",
        At(32768 + 80),
        L(4),
        None,
        None,
    ),
    f(
        "PrimaryVolumeDescriptor.path_table_size",
        "Path table size (LE)",
        At(32768 + 132),
        L(4),
        None,
        None,
    ),
    f(
        "PrimaryVolumeDescriptor.path_table_location",
        "L-path table location (LBA)",
        At(32768 + 140),
        L(4),
        None,
        None,
    ),
];

/// GZIP field map (RFC 1952).
pub static GZIP_FIELDS: &[FieldDef] = &[
    f(
        "gzip.magic",
        "Magic bytes",
        At(0),
        L(2),
        Some(&[0x1F, 0x8B]),
        None,
    ),
    f(
        "gzip.cm",
        "Compression method",
        At(2),
        L(1),
        Some(&[8]),
        Some((8, 8)),
    ),
    f("gzip.flags", "Flags", At(3), L(1), None, None),
    f(
        "gzip.crc32",
        "CRC-32 of uncompressed data (trailer)",
        FromEnd(8),
        L(4),
        None,
        None,
    ),
    f(
        "gzip.isize",
        "Uncompressed size mod 2^32 (trailer)",
        FromEnd(4),
        L(4),
        None,
        None,
    ),
];

/// RAR field map (RAR5 signature only; full parser is a later phase).
pub static RAR_FIELDS: &[FieldDef] = &[f(
    "rar.signature",
    "RAR signature",
    At(0),
    L(8),
    Some(&[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00]),
    None,
)];

/// 7-Zip field map (signature header only).
pub static SEVENZ_FIELDS: &[FieldDef] = &[f(
    "sevenz.signature",
    "7z signature",
    At(0),
    L(6),
    Some(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]),
    None,
)];

/// PDF field map (stub).
pub static PDF_FIELDS: &[FieldDef] = &[f(
    "pdf.header",
    "PDF header",
    At(0),
    L(5),
    Some(b"%PDF-"),
    None,
)];

/// SQLite field map (stub).
pub static SQLITE_FIELDS: &[FieldDef] = &[
    f(
        "sqlite.magic",
        "Header magic",
        At(0),
        L(16),
        Some(b"SQLite format 3\0"),
        None,
    ),
    f(
        "sqlite.page_size",
        "Page size (BE)",
        At(16),
        L(2),
        None,
        None,
    ),
];

/// Return the field map for a format label (`"ZIP"`, `"TAR"`, ...).
pub fn fields_for(format: &str) -> &'static [FieldDef] {
    match format {
        "ZIP" => ZIP_FIELDS,
        "TAR" => TAR_FIELDS,
        "ISO" => ISO_FIELDS,
        "GZIP" => GZIP_FIELDS,
        "RAR" => RAR_FIELDS,
        "7Z" => SEVENZ_FIELDS,
        "PDF" => PDF_FIELDS,
        "SQLite" => SQLITE_FIELDS,
        _ => &[],
    }
}

/// Look up a field by name across all known maps.
pub fn field(name: &str) -> Option<&'static FieldDef> {
    [
        ZIP_FIELDS,
        TAR_FIELDS,
        ISO_FIELDS,
        GZIP_FIELDS,
        RAR_FIELDS,
        SEVENZ_FIELDS,
        PDF_FIELDS,
        SQLITE_FIELDS,
    ]
    .iter()
    .flat_map(|m| m.iter())
    .find(|f| f.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zip_eocd_signature_expected() {
        let f = field("EOCD.signature").unwrap();
        assert_eq!(f.expected_value, Some(&[0x50, 0x4B, 0x05, 0x06][..]));
        assert_eq!(f.offset_rule, FromEnd(22));
    }

    #[test]
    fn iso_magic_present() {
        assert!(fields_for("ISO")
            .iter()
            .any(|f| f.name == "PrimaryVolumeDescriptor.magic"));
    }

    #[test]
    fn unknown_format_empty() {
        assert!(fields_for("NOPE").is_empty());
    }
}
