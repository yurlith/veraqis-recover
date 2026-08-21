//! Stage 2 — Format detection by magic bytes.
//!
//! - `PK\x03\x04` / `PK\x05\x06` / `PK\x07\x08` at offset 0 → ZIP
//! - `ustar` at offset 257 → TAR
//! - `CD001` at offset 32769 → ISO 9660
//! - `1F 8B` at offset 0 → GZIP
//! - `SQLite format 3\0` at offset 0 → SQLite
//! - `37 7A BC AF 27 1C` at offset 0 → 7-Zip
//! - `Rar!\x1A\x07` at offset 0 → RAR (RAR4 `..00` / RAR5 `..01 00`)
//! - PDF/BZIP2/XZ/ZSTD/LZ4 signatures at offset 0 → their exact stream format
//! - `.gz` extension with no other match → GZIP (allows GZ_MAGIC_001 to fire)
//! - `.db`/`.sqlite`/`.sqlite3` extension → SQLite (allows SQ_MAGIC_001 to fire)
//! - otherwise → Raw

use crate::model::ArchiveFormat;
use crate::reader::DataSource;
use phx_format_id::Format;

/// Translate the shared table's format into this crate's, or `None` when this engine has no
/// reader for it.
///
/// `None` is not a gap to be filled in silently. The table can *name* more formats than this
/// engine can *read* — CAB, WIM and QCOW2 are named so the browser checker can tell a person
/// what their file is, and returning `ArchiveFormat::Raw` for them here is the honest
/// outcome: nothing in this crate parses them, so nothing here may claim to.
///
/// Deliberately exhaustive. Adding a format to `phx_format_id` will not compile until it is
/// routed — to a reader if one exists, to `None` if not — because a format the table can
/// name while the engine quietly drops it is exactly the drift this arrangement exists to
/// prevent.
fn from_shared(f: Format) -> Option<ArchiveFormat> {
    match f {
        Format::Zip => Some(ArchiveFormat::Zip),
        Format::Tar => Some(ArchiveFormat::Tar),
        Format::Iso9660 => Some(ArchiveFormat::Iso9660),
        Format::Gzip => Some(ArchiveFormat::Gzip),
        Format::Sqlite => Some(ArchiveFormat::Sqlite),
        Format::SevenZ => Some(ArchiveFormat::SevenZ),
        Format::Rar => Some(ArchiveFormat::Rar),
        Format::Pdf => Some(ArchiveFormat::Pdf),
        Format::Bzip2 => Some(ArchiveFormat::Bzip2),
        Format::Xz => Some(ArchiveFormat::Xz),
        Format::Zstd => Some(ArchiveFormat::Zstd),
        Format::Lz4 => Some(ArchiveFormat::Lz4),
        // Named by the shared table, not read by this engine. Backups and virtual disks:
        // the browser checker tells a person what their file is, and nothing here pretends
        // to open it.
        Format::Cab
        | Format::Wim
        | Format::Qcow2
        | Format::Vhd
        | Format::Vhdx
        | Format::Vmdk
        | Format::Dmg
        | Format::AcronisTib
        | Format::MacriumX => None,
    }
}

/// Detect the container format of `source`.
///
/// The magic-byte half is `phx_format_id::identify` — the same table the browser checker is
/// generated from, so the two products cannot drift into telling a user different things
/// about the same bytes. The extension fallbacks below stay here, because they are this
/// crate's own concern: they exist so a file whose signature was *destroyed* still routes to
/// its format's rules and recovery strategies instead of being demoted to a healthy Raw
/// file. That is right for recovery routing and wrong for telling a person what they have,
/// which is why the shared table refuses to fold the two together.
pub fn detect(source: &DataSource) -> ArchiveFormat {
    // Two bounded reads decide the whole table. The tail is what makes a fixed VHD, a DMG
    // and a Macrium image nameable at all — their only identity lives in a footer — and it
    // costs one 512-byte read regardless of how large the file is.
    let mut head = vec![0u8; phx_format_id::REQUIRED_PREFIX];
    let n = source.read_at(0, &mut head).unwrap_or(0);
    head.truncate(n);

    let total_len = source.len();
    let suffix = phx_format_id::REQUIRED_SUFFIX as u64;
    let tail = if total_len > suffix {
        source
            .read_exact_at(total_len - suffix, suffix as usize)
            .unwrap_or_default()
    } else {
        head.clone()
    };

    let bytes = phx_format_id::Bytes {
        head: &head,
        tail: &tail,
        total_len,
    };

    // A positive identification this engine can read settles it. One it cannot read falls
    // through to the extension fallbacks below and, failing those, to Raw — the same place
    // an unrecognised file has always landed, so naming more formats upstream cannot change
    // what this engine does with them.
    if let Some(af) = phx_format_id::identify(bytes).and_then(from_shared) {
        return af;
    }

    // Extension fallback: treat `.gz` / `.tgz` files that failed all magic checks
    // as GZIP so the GZ_MAGIC_001 rule can fire on corrupted magic bytes.
    if has_gz_extension(source) {
        return ArchiveFormat::Gzip;
    }

    // Extension fallback: treat `.db` / `.sqlite` / `.sqlite3` as SQLite so
    // SQ_MAGIC_001 can fire on files with corrupted header magic.
    if has_sqlite_extension(source) {
        return ArchiveFormat::Sqlite;
    }

    // Extension fallback for the stream archives, so the *_MAGIC_001 rules can
    // fire on files whose signature was corrupted.
    let path = source.path().to_string_lossy().to_ascii_lowercase();
    if path.ends_with(".7z") {
        return ArchiveFormat::SevenZ;
    }
    if path.ends_with(".rar") {
        return ArchiveFormat::Rar;
    }
    if path.ends_with(".pdf") {
        return ArchiveFormat::Pdf;
    }
    if path.ends_with(".bz2") {
        return ArchiveFormat::Bzip2;
    }
    if path.ends_with(".xz") {
        return ArchiveFormat::Xz;
    }
    if path.ends_with(".zst") || path.ends_with(".zstd") {
        return ArchiveFormat::Zstd;
    }
    if path.ends_with(".lz4") {
        return ArchiveFormat::Lz4;
    }

    // Extension fallback for ZIP/OPC, TAR and ISO — the same pattern as the
    // gz/sqlite/7z/rar fallbacks above, so a file whose signature bytes were
    // destroyed still routes to its format's rules (and, downstream, to its
    // recovery strategies: a ZIP's central directory / EOCD, a TAR's later
    // headers, an ISO's descriptors typically survive a damaged head).
    // Before this fallback such files fell to Raw and were reported "healthy",
    // hiding the damage — the opposite of this product's honesty contract.
    const ZIP_EXTS: &[&str] = &[".zip", ".jar", ".apk", ".docx", ".xlsx", ".pptx", ".epub"];
    if ZIP_EXTS.iter().any(|e| path.ends_with(e)) {
        return ArchiveFormat::Zip;
    }
    if path.ends_with(".tar") {
        return ArchiveFormat::Tar;
    }
    if path.ends_with(".iso") {
        return ArchiveFormat::Iso9660;
    }

    ArchiveFormat::Raw
}

fn has_gz_extension(source: &DataSource) -> bool {
    let path = source.path().to_string_lossy().to_ascii_lowercase();
    path.ends_with(".gz") || path.ends_with(".tgz")
}

fn has_sqlite_extension(source: &DataSource) -> bool {
    let path = source.path().to_string_lossy().to_ascii_lowercase();
    path.ends_with(".db") || path.ends_with(".sqlite") || path.ends_with(".sqlite3")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_zip_local_header() {
        let src = DataSource::from_bytes("z", b"PK\x03\x04rest".to_vec());
        assert_eq!(detect(&src), ArchiveFormat::Zip);
    }

    #[test]
    fn detects_raw_for_unknown() {
        let src = DataSource::from_bytes("r", vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(detect(&src), ArchiveFormat::Raw);
    }

    #[test]
    fn detects_iso_at_pvd() {
        // Offset taken from the shared table rather than restated, so moving it there
        // cannot leave this test passing against a number nothing uses any more.
        let iso = phx_format_id::SIGNATURES
            .iter()
            .find(|s| s.format == Format::Iso9660)
            .expect("the table names ISO 9660");
        let src = DataSource::from_bytes("i", specimen_for(iso));
        assert_eq!(detect(&src), ArchiveFormat::Iso9660);
    }

    /// The smallest file a rule can fire on, built from the rule itself so a new rule is
    /// exercised the day it is added. End-anchored rules are padded past their anchor depth
    /// so the magic does not also land at offset 0 — VHD carries the same cookie under both
    /// anchors, and a specimen where they coincide proves nothing about either.
    fn specimen_for(s: &phx_format_id::Signature) -> Vec<u8> {
        use phx_format_id::Anchor;
        let len = s.min_len.max(match s.anchor {
            Anchor::Start(at) => at + s.magic.len(),
            Anchor::End(back) => back + 64,
        });
        let mut v = vec![0u8; len];
        let at = match s.anchor {
            Anchor::Start(at) => at,
            Anchor::End(back) => len - back,
        };
        v[at..at + s.magic.len()].copy_from_slice(s.magic);
        v
    }

    /// The engine and the shared table must agree wherever the table speaks *and* this
    /// engine has a reader. The engine may say more — its extension fallbacks are
    /// deliberately damage-tolerant — but it must never contradict the bytes.
    #[test]
    fn conformance_with_the_shared_table() {
        for s in phx_format_id::SIGNATURES {
            let Some(expected) = from_shared(s.format) else {
                continue; // covered by named_but_unreadable_formats_stay_raw below
            };
            // A deliberately contradicting name: content must win over it every time.
            let src = DataSource::from_bytes("misleading.rar", specimen_for(s));
            assert_eq!(
                detect(&src),
                expected,
                "engine disagreed with the table on {:?}",
                s.format
            );
        }
    }

    /// A format the table names but this engine cannot read must come back `Raw`, not
    /// something adjacent. Reporting a CAB as, say, a ZIP because both are archives would
    /// hand every downstream rule a file it cannot parse and call the result a finding.
    #[test]
    fn named_but_unreadable_formats_stay_raw() {
        let unreadable: Vec<_> = phx_format_id::SIGNATURES
            .iter()
            .filter(|s| from_shared(s.format).is_none())
            .collect();
        assert!(!unreadable.is_empty(), "the split under test must exist");

        for s in unreadable {
            // A neutral name, so the extension fallbacks have nothing to say either.
            let src = DataSource::from_bytes("specimen.bin", specimen_for(s));
            assert_eq!(
                detect(&src),
                ArchiveFormat::Raw,
                "{:?} is named by the table but unreadable here, so it must stay Raw",
                s.format
            );
        }
    }

    #[test]
    fn detects_7z_magic() {
        let src = DataSource::from_bytes("a.7z", b"\x37\x7A\xBC\xAF\x27\x1C\x00\x04rest".to_vec());
        assert_eq!(detect(&src), ArchiveFormat::SevenZ);
    }

    #[test]
    fn detects_rar4_and_rar5_magic() {
        let r4 = DataSource::from_bytes("a.rar", b"\x52\x61\x72\x21\x1A\x07\x00more".to_vec());
        assert_eq!(detect(&r4), ArchiveFormat::Rar);
        let r5 = DataSource::from_bytes("a.rar", b"\x52\x61\x72\x21\x1A\x07\x01\x00more".to_vec());
        assert_eq!(detect(&r5), ArchiveFormat::Rar);
    }

    #[test]
    fn detects_pdf_and_single_stream_formats_by_magic_and_damaged_extension() {
        let cases: [(&str, &[u8], ArchiveFormat); 5] = [
            ("a.pdf", b"%PDF-1.7", ArchiveFormat::Pdf),
            ("a.bz2", b"BZh91AY", ArchiveFormat::Bzip2),
            (
                "a.xz",
                &[0xFD, b'7', b'z', b'X', b'Z', 0],
                ArchiveFormat::Xz,
            ),
            ("a.zst", &[0x28, 0xB5, 0x2F, 0xFD], ArchiveFormat::Zstd),
            ("a.lz4", &[0x04, 0x22, 0x4D, 0x18], ArchiveFormat::Lz4),
        ];
        for (name, magic, format) in cases {
            assert_eq!(
                detect(&DataSource::from_bytes(name, magic.to_vec())),
                format,
                "{name}"
            );
            assert_eq!(
                detect(&DataSource::from_bytes(name, vec![0u8; 64])),
                format,
                "damaged {name}"
            );
        }
    }

    #[test]
    fn extension_fallback_for_corrupted_7z_and_rar_magic() {
        // Corrupted signatures still route by extension so the *_MAGIC_001 rules fire.
        let z = DataSource::from_bytes("broken.7z", vec![0u8; 64]);
        assert_eq!(detect(&z), ArchiveFormat::SevenZ);
        let r = DataSource::from_bytes("broken.rar", vec![0u8; 64]);
        assert_eq!(detect(&r), ArchiveFormat::Rar);
    }

    #[test]
    fn extension_fallback_for_corrupted_zip_tar_iso_magic() {
        // A destroyed signature must not demote a damaged archive to "Raw /
        // healthy" — route by extension so the format's rules and recovery
        // strategies engage (same pattern as gz/sqlite/7z/rar above).
        for name in [
            "broken.zip",
            "broken.jar",
            "broken.apk",
            "broken.docx",
            "broken.xlsx",
            "broken.pptx",
            "broken.epub",
        ] {
            let s = DataSource::from_bytes(name, vec![0u8; 64]);
            assert_eq!(detect(&s), ArchiveFormat::Zip, "{name}");
        }
        let t = DataSource::from_bytes("broken.tar", vec![0u8; 600]);
        assert_eq!(detect(&t), ArchiveFormat::Tar);
        let i = DataSource::from_bytes("broken.iso", vec![0u8; 40_000]);
        assert_eq!(detect(&i), ArchiveFormat::Iso9660);
        // Content magic still wins over a contradicting extension.
        let z = DataSource::from_bytes("really.zip", b"\x1F\x8B\x08rest".to_vec());
        assert_eq!(detect(&z), ArchiveFormat::Gzip);
        // And unknown content with an unknown extension stays Raw.
        let r = DataSource::from_bytes("noise.bin", vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(detect(&r), ArchiveFormat::Raw);
    }
}
