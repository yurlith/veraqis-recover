//! What a file actually is, decided from its bytes — and, kept separate, what its name
//! claims.
//!
//! # Why this crate exists
//!
//! The magic-byte table had been written three times: `phx_analyze_engine`'s
//! `pipeline::format_detection`, `phx_inspect::detect_format` and `phx_safety`'s own. A
//! fourth was about to be written in JavaScript for the browser checker, which is where a
//! divergence stops being an internal tidiness problem and starts being two products
//! telling a user different things about the same file. The table lives here now, as data,
//! and `phx_analyze_engine` reads it rather than repeating it. A conformance test pins the
//! two to the same answers on a matrix of inputs; the browser's copy is *generated* from
//! [`SIGNATURES`] rather than typed out (`examples/emit_js.rs`), and a test fails if the
//! committed output stops matching. `phx_inspect` and `phx_safety` still carry their own
//! copies — narrower ones, for their own purposes — and are not converted here.
//!
//! # Content and name are answered separately, on purpose
//!
//! The engine's detector folds an extension fallback into its result, and it is right to:
//! a `.zip` whose signature was destroyed must still route to ZIP recovery, or the damage
//! it has is hidden behind a "healthy raw file" verdict.
//!
//! For a user looking at a file, that same fold would be a lie. "This is a ZIP" and "this
//! is named .zip and we could not read its signature" are different statements, and the
//! second is the one that explains why nothing opens it. So this crate returns both and
//! never merges them — [`identify`] reads only bytes, [`from_extension`] reads only the
//! name, and [`Identification::agreement`] says whether they agree. Callers that need the
//! engine's damage-tolerant routing compose the two themselves and stay honest about which
//! answer they used.

#![forbid(unsafe_code)]

/// A container or stream format this project can name.
///
/// The identifiers match `phx_analyze_engine::ArchiveFormat::as_str`, so a value crossing
/// between the two needs no translation table — the thing that would go stale first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Format {
    Zip,
    Tar,
    Iso9660,
    Gzip,
    Sqlite,
    SevenZ,
    Rar,
    Pdf,
    Bzip2,
    Xz,
    Zstd,
    Lz4,
    // Backup, imaging and virtual disks. The engine has no reader for any of these, which
    // is why `phx_analyze_engine` maps them to `None`: naming a format is a smaller claim
    // than reading one, and the two must not be conflated. How each signature came to be
    // believed — measured here, or taken from published documentation — is recorded per
    // rule in [`SIGNATURES`] and travels with the answer.
    Cab,
    Wim,
    Qcow2,
    Vhd,
    Vhdx,
    Vmdk,
    Dmg,
    AcronisTib,
    MacriumX,
}

impl Format {
    pub fn as_str(self) -> &'static str {
        match self {
            Format::Zip => "zip",
            Format::Tar => "tar",
            Format::Iso9660 => "iso9660",
            Format::Gzip => "gzip",
            Format::Sqlite => "sqlite",
            Format::SevenZ => "7z",
            Format::Rar => "rar",
            Format::Pdf => "pdf",
            Format::Bzip2 => "bzip2",
            Format::Xz => "xz",
            Format::Zstd => "zstd",
            Format::Lz4 => "lz4",
            Format::Cab => "cab",
            Format::Wim => "wim",
            Format::Qcow2 => "qcow2",
            Format::Vhd => "vhd",
            Format::Vhdx => "vhdx",
            Format::Vmdk => "vmdk",
            Format::Dmg => "dmg",
            Format::AcronisTib => "acronis_tib",
            Format::MacriumX => "macrium_x",
        }
    }

    /// What to call it to a person.
    pub fn label(self) -> &'static str {
        match self {
            Format::Zip => "ZIP archive",
            Format::Tar => "TAR archive",
            Format::Iso9660 => "ISO 9660 disc image",
            Format::Gzip => "gzip stream",
            Format::Sqlite => "SQLite database",
            Format::SevenZ => "7-Zip archive",
            Format::Rar => "RAR archive",
            Format::Pdf => "PDF document",
            Format::Bzip2 => "bzip2 stream",
            Format::Xz => "xz stream",
            Format::Zstd => "Zstandard stream",
            Format::Lz4 => "LZ4 stream",
            Format::Cab => "Microsoft Cabinet archive",
            Format::Wim => "Windows image (WIM)",
            Format::Qcow2 => "QCOW2 disk image",
            Format::Vhd => "VHD virtual disk",
            Format::Vhdx => "VHDX virtual disk",
            Format::Vmdk => "VMDK virtual disk",
            Format::Dmg => "Apple disk image (DMG)",
            Format::AcronisTib => "Acronis True Image backup",
            Format::MacriumX => "Macrium Reflect X image",
        }
    }

    /// Whether the format holds many members that can be reported one by one. A gzip or xz
    /// stream holds exactly one, which is why "3 of 12 entries verified" cannot be said
    /// about them however healthy they are.
    pub fn is_multi_member(self) -> bool {
        matches!(
            self,
            Format::Zip
                | Format::Tar
                | Format::Iso9660
                | Format::SevenZ
                | Format::Rar
                | Format::Cab
                | Format::Wim
        )
    }

    /// File extensions conventionally used for this format, lowercase, with the dot.
    ///
    /// Used only to read a *name*, never to decide what a file is.
    pub fn extensions(self) -> &'static [&'static str] {
        match self {
            Format::Zip => &[
                ".zip", ".jar", ".apk", ".docx", ".xlsx", ".pptx", ".epub", ".odt", ".ods",
            ],
            Format::Tar => &[".tar"],
            Format::Iso9660 => &[".iso"],
            Format::Gzip => &[".gz", ".tgz"],
            Format::Sqlite => &[".db", ".sqlite", ".sqlite3"],
            Format::SevenZ => &[".7z"],
            Format::Rar => &[".rar"],
            Format::Pdf => &[".pdf"],
            Format::Bzip2 => &[".bz2"],
            Format::Xz => &[".xz"],
            Format::Zstd => &[".zst", ".zstd"],
            Format::Lz4 => &[".lz4"],
            Format::Cab => &[".cab"],
            Format::Wim => &[".wim"],
            Format::Qcow2 => &[".qcow2", ".qcow"],
            Format::Vhd => &[".vhd"],
            Format::Vhdx => &[".vhdx", ".avhdx"],
            Format::Vmdk => &[".vmdk"],
            Format::Dmg => &[".dmg"],
            Format::AcronisTib => &[".tib"],
            Format::MacriumX => &[".mrimgx", ".mrbakx"],
        }
    }
}

/// Shorthand for the table below, which is long enough already without two struct variants
/// spelled out on every line.
const fn m(specimen: &'static str) -> Provenance {
    Provenance::Measured { specimen }
}
const fn d(source: &'static str, caveat: Option<&'static str>) -> Provenance {
    Provenance::Documented { source, caveat }
}

/// Where a magic sits. Not every format stamps its identity at the front.
///
/// A fixed-size VHD carries its only cookie in a 512-byte footer; a DMG's `koly` trailer and
/// a Macrium image's `MACRIUM_FILE` are likewise at the end. A start-anchored table cannot
/// name any of them — not because the formats are obscure, but because the table was the
/// wrong shape. Both anchors are bounded reads: a head and a tail, never a scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Anchor {
    /// `magic` begins this many bytes after the start of the file.
    Start(usize),
    /// `magic` begins this many bytes *before* the end of the file. `End(512)` means the
    /// magic occupies bytes `len-512 ..`, which is how a 512-byte footer is addressed.
    End(usize),
}

/// How this project came to believe a signature, kept in the type system rather than in a
/// comment someone will stop reading.
///
/// Signature tables circulate widely and are copied far more often than they are checked, so
/// "we saw it" and "someone published it" are different claims and must not be flattened
/// into one. Both are legitimate; only one is a measurement. What is forbidden is a rule
/// that can cite neither — and the `every_signature_can_account_for_itself` test enforces
/// exactly that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// Read off a real file. `specimen` names it precisely enough to find again.
    Measured { specimen: &'static str },
    /// Taken from a published specification or a reader implementation, and NOT verified
    /// here against a real file of that format. `source` cites it; `caveat` records any
    /// stated limit of that source, because "documented" is not the same as "documented
    /// without qualification".
    Documented {
        source: &'static str,
        caveat: Option<&'static str>,
    },
}

impl Provenance {
    pub fn is_measured(self) -> bool {
        matches!(self, Provenance::Measured { .. })
    }

    /// A short label a person can read, for a tool that must not present a citation as an
    /// observation.
    pub fn label(self) -> &'static str {
        match self {
            Provenance::Measured { .. } => "measured on a real file",
            Provenance::Documented { .. } => "from published documentation, not verified here",
        }
    }
}

/// One magic-byte rule.
#[derive(Debug, Clone, Copy)]
pub struct Signature {
    pub format: Format,
    pub anchor: Anchor,
    pub magic: &'static [u8],
    /// The shortest file this rule may fire on. Usually just enough to hold the magic at its
    /// anchor; larger when a rule needs bytes it does not compare — RAR's version byte
    /// follows its six-byte stamp and decides RAR4 from RAR5, so six bytes is not enough to
    /// call something a RAR.
    pub min_len: usize,
    pub provenance: Provenance,
}

/// Every rule, in the order they are tried. First match wins.
///
/// The order is not alphabetical and must not be sorted: it is the engine's, preserved so
/// that a file matching two rules resolves the same way in both. The
/// `conformance_with_the_shared_table` test in `phx_analyze_engine` fails if that stops
/// being true.
///
/// One rule per line is deliberate — rustfmt's six-lines-per-entry expansion makes an
/// ordered list impossible to scan for the thing that matters here, which is what comes
/// before what.
#[rustfmt::skip]
pub const SIGNATURES: &[Signature] = &[
    // ZIP records: local header, end-of-central-directory, data descriptor. Only three
    // bytes are compared, matching the engine — the fourth varies across writers.
    // --- measured here, on this machine -------------------------------------------------
    // Every rule in this block was read off a real file. The specimen is named so the claim
    // can be re-checked rather than trusted.
    Signature { format: Format::Zip, anchor: Anchor::Start(0), magic: b"PK\x03", min_len: 4, provenance: m("the project's own ZIP corpus (2268 files)") },
    Signature { format: Format::Zip, anchor: Anchor::Start(0), magic: b"PK\x05", min_len: 4, provenance: m("the project's own ZIP corpus (2268 files)") },
    Signature { format: Format::Zip, anchor: Anchor::Start(0), magic: b"PK\x07", min_len: 4, provenance: m("the project's own ZIP corpus (2268 files)") },
    Signature { format: Format::Gzip, anchor: Anchor::Start(0), magic: &[0x1F, 0x8B], min_len: 2, provenance: m("engine corpus, gzip members") },
    Signature { format: Format::Sqlite, anchor: Anchor::Start(0), magic: b"SQLite format 3\0", min_len: 16, provenance: m("engine corpus, sqlite databases") },
    Signature { format: Format::Pdf, anchor: Anchor::Start(0), magic: b"%PDF-", min_len: 5, provenance: m("engine corpus, pdf documents") },
    Signature { format: Format::Bzip2, anchor: Anchor::Start(0), magic: b"BZh", min_len: 3, provenance: m("engine corpus, bzip2 streams") },
    Signature { format: Format::Xz, anchor: Anchor::Start(0), magic: &[0xFD, b'7', b'z', b'X', b'Z', 0x00], min_len: 6, provenance: m("engine corpus, xz streams") },
    Signature { format: Format::Zstd, anchor: Anchor::Start(0), magic: &[0x28, 0xB5, 0x2F, 0xFD], min_len: 4, provenance: m("engine corpus, zstd streams") },
    Signature { format: Format::Lz4, anchor: Anchor::Start(0), magic: &[0x04, 0x22, 0x4D, 0x18], min_len: 4, provenance: m("engine corpus, lz4 streams") },
    Signature { format: Format::SevenZ, anchor: Anchor::Start(0), magic: &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], min_len: 6, provenance: m("engine corpus, 7-Zip archives") },
    Signature { format: Format::Rar, anchor: Anchor::Start(0), magic: &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07], min_len: 7, provenance: m("engine corpus, RAR archives") },
    Signature { format: Format::Cab, anchor: Anchor::Start(0), magic: b"MSCF", min_len: 4, provenance: m(r"C:\Windows\Logs\CBS\CbsPersist_*.cab") },
    Signature { format: Format::Wim, anchor: Anchor::Start(0), magic: b"MSWIM\0\0\0", min_len: 8, provenance: m(r"C:\Windows\System32\DrtmAuthTxt.wim") },
    Signature { format: Format::Qcow2, anchor: Anchor::Start(0), magic: &[0x51, 0x46, 0x49, 0xFB], min_len: 4, provenance: m("~/.android/avd/*.avd/cache.img.qcow2") },

    // --- documented, not verified here ---------------------------------------------------
    // Backup and virtual-disk formats nobody here has a specimen of. Each cites where its
    // bytes come from, and `Provenance::Documented` keeps that distinction all the way to
    // the user rather than letting a citation be displayed as an observation.
    Signature { format: Format::Vhdx, anchor: Anchor::Start(0), magic: b"vhdxfile", min_len: 8, provenance: d("Microsoft [MS-VHDX] §2.1 File Type Identifier; matches libyal/libvhdi and qemu block/vhdx.h", None) },
    // A dynamic or differencing VHD opens with a copy of its 512-byte footer, so the cookie
    // is readable at the front. A FIXED VHD has no header at all — its only cookie is the
    // footer, which is why the same magic appears twice here with two anchors. One table
    // shape short of this and half of all VHDs are unnameable.
    Signature { format: Format::Vhd, anchor: Anchor::Start(0), magic: b"conectix", min_len: 512, provenance: d("Microsoft Virtual Hard Disk Image Format Specification — footer copy at the head of dynamic/differencing disks", Some("fixed-size VHDs have no header copy; they match the End(512) rule below")) },
    Signature { format: Format::Vmdk, anchor: Anchor::Start(0), magic: b"KDMV", min_len: 512, provenance: d("VMware sparse extent header magic 0x564D444B; matches libyal/libvmdk and qemu block/vmdk.c", Some("monolithic-flat VMDKs are a plain-text descriptor plus a raw extent and carry no magic")) },
    Signature { format: Format::AcronisTib, anchor: Anchor::Start(0), magic: &[0xCE, 0x24, 0xB9, 0xA2, 0x20, 0x00, 0x00, 0x00], min_len: 8, provenance: d("file(1) magic database submission, 2018-11 (Magdir/archive)", Some("author verified True Image 2013 and 2019 only; older builds use a different stamp, and TIBX is a separate format")) },

    // --- end-anchored --------------------------------------------------------------------
    // These exist at all only because the table grew an End anchor.
    Signature { format: Format::Vhd, anchor: Anchor::End(512), magic: b"conectix", min_len: 512, provenance: d("Microsoft Virtual Hard Disk Image Format Specification — the 512-byte footer every VHD ends with", None) },
    Signature { format: Format::Dmg, anchor: Anchor::End(512), magic: b"koly", min_len: 512, provenance: d("UDIF trailer, 0x6B6F6C79; matches libyal/libmodi and qemu block/dmg.c", Some("qemu searches a small window rather than a fixed offset, so an image with padding after the trailer will not match this rule")) },
    Signature { format: Format::MacriumX, anchor: Anchor::End(12), magic: b"MACRIUM_FILE", min_len: 20, provenance: d("macrium/mrimgx_file_layout, docs/FILE_LAYOUT.md: struct Footer { uint64 first_metadata_block_header; uint8 magic_bytes[12]; }", Some("Reflect X (.mrimgx/.mrbakx) only; the legacy .mrimg format has no dependable signature")) },

    // --- inside the file, neither end ------------------------------------------------------
    // The stamp sits inside the first header block / the primary volume descriptor. This is
    // why identification needs a prefix rather than a handful of bytes.
    Signature { format: Format::Tar, anchor: Anchor::Start(257), magic: b"ustar", min_len: 263, provenance: m("engine corpus, tar archives") },
    Signature { format: Format::Iso9660, anchor: Anchor::Start(32769), magic: b"CD001", min_len: 32775, provenance: m("engine corpus, ISO 9660 images") },
];

/// The shortest prefix that can decide every start-anchored rule in [`SIGNATURES`].
///
/// A caller reading a file off a disk or over a `File` handle needs to know how much to
/// read; ISO 9660's descriptor at 32769 is what sets it.
pub const REQUIRED_PREFIX: usize = 32775;

/// The shortest suffix that can decide every end-anchored rule.
///
/// Two bounded reads, a head and a tail, are enough for the whole table. Nothing here ever
/// scans, so identifying a 500 GB backup image costs the same as identifying a 3 KB one.
pub const REQUIRED_SUFFIX: usize = 512;

/// The bytes of a file a rule can be tested against: a bounded head, a bounded tail, and
/// how long the file actually is.
///
/// `total_len` is not derivable from the two slices and is not optional. An end-anchored
/// rule is a statement about a position relative to the end of the *file*, so a caller that
/// hands over a tail without saying what it is the tail of is asking for a guess.
#[derive(Debug, Clone, Copy)]
pub struct Bytes<'a> {
    /// The first bytes of the file, up to [`REQUIRED_PREFIX`]. May be shorter.
    pub head: &'a [u8],
    /// The last bytes of the file, up to [`REQUIRED_SUFFIX`]. May be shorter, and may
    /// overlap `head` entirely for a small file — that is correct, not a special case.
    pub tail: &'a [u8],
    pub total_len: u64,
}

impl<'a> Bytes<'a> {
    /// For a file small enough to hold entirely, where head and tail are the same slice.
    pub fn whole(all: &'a [u8]) -> Self {
        Bytes {
            head: all,
            tail: all,
            total_len: all.len() as u64,
        }
    }

    /// The window `magic` would occupy under `anchor`, or `None` when the bytes to check it
    /// were not supplied or do not exist.
    fn window(&self, anchor: Anchor, len: usize) -> Option<&'a [u8]> {
        match anchor {
            Anchor::Start(at) => self.head.get(at..at.checked_add(len)?),
            Anchor::End(back) => {
                // Where the magic starts, counted from the end of the file, then translated
                // into the tail slice we were actually given. Checked throughout: a short
                // tail must fail to match, never wrap into a wrong offset.
                let from_end = back;
                if (from_end as u64) > self.total_len || from_end > self.tail.len() {
                    return None;
                }
                let at = self.tail.len().checked_sub(from_end)?;
                self.tail.get(at..at.checked_add(len)?)
            }
        }
    }
}

/// What the bytes say. `None` means no rule matched — which is a real answer ("this is not
/// a format we know"), not a failure.
///
/// Every rule is checked against bytes that were actually supplied: one needing a tail that
/// was not read simply does not fire. A truncated or partial read can therefore only ever
/// produce `None`, never a wrong format.
pub fn identify(bytes: Bytes<'_>) -> Option<Format> {
    identify_with_provenance(bytes).map(|(f, _)| f)
}

/// The format and *how this project came to believe that signature*.
///
/// Any tool that shows the answer to a person should use this rather than [`identify`]: the
/// difference between "we have seen this on a real file" and "a specification says so" is
/// exactly the difference a user needs when the answer surprises them.
pub fn identify_with_provenance(bytes: Bytes<'_>) -> Option<(Format, Provenance)> {
    SIGNATURES
        .iter()
        .find(|s| {
            bytes.total_len >= s.min_len as u64
                && bytes
                    .window(s.anchor, s.magic.len())
                    .is_some_and(|w| w == s.magic)
        })
        .map(|s| (s.format, s.provenance))
}

/// What the name claims. Case-insensitive; the longest matching extension wins so that
/// `.sqlite3` is not read as `.sqlite`.
pub fn from_extension(name: &str) -> Option<Format> {
    let lower = name.to_ascii_lowercase();
    let mut best: Option<(usize, Format)> = None;
    for sig_format in FORMATS {
        for ext in sig_format.extensions() {
            if lower.ends_with(ext) && best.is_none_or(|(len, _)| ext.len() > len) {
                best = Some((ext.len(), *sig_format));
            }
        }
    }
    best.map(|(_, f)| f)
}

/// Every format, for iteration. Kept next to `Format` so adding a variant that is not
/// listed here fails the `every_format_is_listed` test rather than silently disappearing
/// from extension lookup and from the generated browser table.
pub const FORMATS: &[Format] = &[
    Format::Zip,
    Format::Tar,
    Format::Iso9660,
    Format::Gzip,
    Format::Sqlite,
    Format::SevenZ,
    Format::Rar,
    Format::Pdf,
    Format::Bzip2,
    Format::Xz,
    Format::Zstd,
    Format::Lz4,
    Format::Cab,
    Format::Wim,
    Format::Qcow2,
    Format::Vhd,
    Format::Vhdx,
    Format::Vmdk,
    Format::Dmg,
    Format::AcronisTib,
    Format::MacriumX,
];

/// How the bytes and the name relate. The interesting values are the disagreements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agreement {
    /// Both say the same format.
    Match,
    /// Both spoke and they disagree — the extension is wrong, or the file was renamed.
    /// Content wins, always.
    Mismatch,
    /// The bytes identify it; the name says nothing (no extension, or an unknown one).
    ContentOnly,
    /// The name claims a format the bytes do not confirm. Usually a damaged signature —
    /// the single most useful thing to be able to say, and the one a content-only detector
    /// cannot say at all.
    NameOnly,
    /// Neither the bytes nor the name identify anything.
    Unknown,
}

/// The pair of answers, kept apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identification {
    pub by_content: Option<Format>,
    pub by_name: Option<Format>,
    /// How the content answer was arrived at. `None` when the content answered nothing —
    /// there is no provenance for a non-answer.
    pub provenance: Option<Provenance>,
}

impl Identification {
    pub fn of(bytes: Bytes<'_>, name: &str) -> Self {
        let found = identify_with_provenance(bytes);
        Identification {
            by_content: found.map(|(f, _)| f),
            provenance: found.map(|(_, p)| p),
            by_name: from_extension(name),
        }
    }

    pub fn agreement(self) -> Agreement {
        match (self.by_content, self.by_name) {
            (Some(c), Some(n)) if c == n => Agreement::Match,
            (Some(_), Some(_)) => Agreement::Mismatch,
            (Some(_), None) => Agreement::ContentOnly,
            (None, Some(_)) => Agreement::NameOnly,
            (None, None) => Agreement::Unknown,
        }
    }

    /// The format to act on, and nothing about how sure we are — callers that report to a
    /// person must use [`Self::agreement`] instead, so that a guess from a file name is
    /// never printed as a fact about the bytes.
    pub fn best_effort(self) -> Option<Format> {
        self.by_content.or(self.by_name)
    }
}

/* ------------------------------------------------------ the browser's copy */

/// Render this table as a self-contained JavaScript module.
///
/// See `examples/emit_js.rs` for why the browser gets a generated copy rather than a call
/// into WebAssembly. The logic below is written out here, once, alongside the data it walks.
pub fn emit_javascript() -> String {
    let mut out = String::new();
    out.push_str(
        "// GENERATED — do not edit. Source of truth: crates/phx_format_id/src/lib.rs\n\
         // Regenerate: cargo run -p phx_format_id --example emit_js\n\
         //\n\
         // What a file actually is, decided from its bytes — and, kept separate, what its\n\
         // name claims. Those are different statements: a RAR named .zip and a .zip whose\n\
         // signature was destroyed both fail a ZIP check, and they need opposite advice.\n\
         //\n\
         // This is a copy of the table the recovery engine uses, generated from it rather\n\
         // than retyped, so the two cannot drift into telling a user different things about\n\
         // the same bytes.\n\n",
    );

    out.push_str(&format!(
        "/** Two bounded reads decide the whole table: this many bytes from the front… */\n\
         export const REQUIRED_PREFIX = {REQUIRED_PREFIX};\n\
         /** …and this many from the end. Nothing here ever scans, so a 500 GB image costs\n\
          *  the same to identify as a 3 KB one. */\n\
         export const REQUIRED_SUFFIX = {REQUIRED_SUFFIX};\n\n"
    ));

    out.push_str(
        "/** Magic-byte rules, in order. First match wins — the order is the engine's.\n\
         \x20*  Do not sort.\n\
         \x20*\n\
         \x20*  `anchor` is 'start' or 'end'; 'end' means `at` counts backwards from EOF, which is\n\
         \x20*  how a footer is addressed (a fixed VHD, a DMG trailer, a Macrium image).\n\
         \x20*\n\
         \x20*  `provenance` is 'measured' when these bytes were read off a real file, and\n\
         \x20*  'documented' when they come from a specification or a reader implementation and\n\
         \x20*  were NOT verified here. Show the difference; do not average it away. */\n\
         export const SIGNATURES = [\n",
    );
    for s in SIGNATURES {
        let magic = s
            .magic
            .iter()
            .map(|b| format!("0x{b:02x}"))
            .collect::<Vec<_>>()
            .join(", ");
        let (anchor, at) = match s.anchor {
            Anchor::Start(n) => ("start", n),
            Anchor::End(n) => ("end", n),
        };
        let (kind, note) = match s.provenance {
            Provenance::Measured { specimen } => ("measured", specimen),
            Provenance::Documented { source, .. } => ("documented", source),
        };
        let caveat = match s.provenance {
            Provenance::Documented {
                caveat: Some(c), ..
            } => js_string(c),
            _ => "null".to_string(),
        };
        out.push_str(&format!(
            "  {{ format: '{}', anchor: '{}', at: {}, minLen: {}, magic: [{}], provenance: '{}', source: {}, caveat: {} }},\n",
            s.format.as_str(),
            anchor,
            at,
            s.min_len,
            magic,
            kind,
            js_string(note),
            caveat,
        ));
    }
    out.push_str("];\n\n");

    out.push_str("/** Everything else worth saying about a format, keyed by its identifier. */\nexport const FORMATS = {\n");
    for f in FORMATS {
        let exts = f
            .extensions()
            .iter()
            .map(|e| format!("'{e}'"))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!(
            "  {}: {{ label: {}, multiMember: {}, extensions: [{}] }},\n",
            js_key(f.as_str()),
            js_string(f.label()),
            f.is_multi_member(),
            exts
        ));
    }
    out.push_str("};\n\n");

    out.push_str(
        r#"/**
 * The bytes a rule is tested against: a bounded head, a bounded tail, and how long the file
 * really is. `totalLen` is required and not derived — an end-anchored rule is a statement
 * about a position relative to the end of the FILE, so a tail handed over without saying
 * what it is the tail of would only produce a guess.
 */
export function bytesOf(head, tail, totalLen) {
  return { head, tail, totalLen };
}

/** For a file small enough to hold entirely, where head and tail are the same array. */
export function whole(all) {
  return { head: all, tail: all, totalLen: all.length };
}

function windowFor(b, s) {
  if (s.anchor === 'start') {
    if (s.at + s.magic.length > b.head.length) return null;
    return { buf: b.head, at: s.at };
  }
  // 'end': `at` counts backwards from EOF. Bail rather than wrap when the tail we were
  // given is shorter than the rule needs.
  if (s.at > b.totalLen || s.at > b.tail.length) return null;
  const at = b.tail.length - s.at;
  if (at + s.magic.length > b.tail.length) return null;
  return { buf: b.tail, at };
}

/** What the bytes say, with how the signature came to be believed. `null` when nothing matched. */
export function identifyDetailed(b) {
  for (const s of SIGNATURES) {
    if (b.totalLen < s.minLen) continue;
    const w = windowFor(b, s);
    if (!w) continue;
    let hit = true;
    for (let i = 0; i < s.magic.length; i++) {
      if (w.buf[w.at + i] !== s.magic[i]) { hit = false; break; }
    }
    if (hit) return { format: s.format, provenance: s.provenance, source: s.source, caveat: s.caveat };
  }
  return null;
}

/** What the bytes say. `null` when nothing matched — a real answer, not a failure. */
export function identify(b) {
  const found = identifyDetailed(b);
  return found && found.format;
}

/** What the name claims. The longest matching extension wins, so `.sqlite3` is not `.sqlite`. */
export function fromExtension(name) {
  const lower = String(name || '').toLowerCase();
  let best = null;
  for (const [id, meta] of Object.entries(FORMATS)) {
    for (const ext of meta.extensions) {
      if (lower.endsWith(ext) && (best === null || ext.length > best.len)) best = { len: ext.length, id };
    }
  }
  return best && best.id;
}

/**
 * Both answers, kept apart, plus how they relate:
 *
 *   match        both say the same thing
 *   mismatch     both spoke and disagree — renamed, or the wrong extension. Content wins.
 *   content-only the bytes identify it; the name says nothing
 *   name-only    the name claims a format the bytes do not confirm — usually a damaged
 *                signature, and the most useful thing there is to be able to say
 *   unknown      neither identifies anything
 */
export function identification(b, name) {
  const found = identifyDetailed(b);
  const byContent = found && found.format;
  const byName = fromExtension(name);
  let agreement;
  if (byContent && byName) agreement = byContent === byName ? 'match' : 'mismatch';
  else if (byContent) agreement = 'content-only';
  else if (byName) agreement = 'name-only';
  else agreement = 'unknown';
  return {
    byContent,
    byName,
    agreement,
    bestEffort: byContent || byName || null,
    // How the content answer was reached. A tool showing this to a person must not present
    // 'documented' as though it were 'measured'.
    provenance: found ? found.provenance : null,
    source: found ? found.source : null,
    caveat: found ? found.caveat : null,
  };
}
"#,
    );
    out
}

fn js_key(id: &str) -> String {
    // `7z` is not a bare identifier.
    if id.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        format!("'{id}'")
    } else {
        id.to_string()
    }
}

fn js_string(s: &str) -> String {
    format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The smallest file a rule can fire on, with its magic in place — start- or
    /// end-anchored. Building it from the rule itself means a new rule is exercised the day
    /// it is added, with no fixture to remember to write.
    fn specimen_for(s: &Signature) -> Vec<u8> {
        let len = s.min_len.max(match s.anchor {
            Anchor::Start(at) => at + s.magic.len(),
            // Deliberately padded past the anchor depth so the magic does NOT land at
            // offset 0. VHD carries the same cookie under both anchors, and a specimen
            // where the two coincide would let a start rule pass a test written for an end
            // rule — the test would then hold even if End were never implemented.
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

    /// The committed browser copy must be what this table renders right now. Without this
    /// the generator is a suggestion: someone adds a format, the engine learns it, and the
    /// checker quietly goes on not knowing — which is the exact failure the shared table
    /// was created to prevent.
    #[test]
    fn generated_file_is_up_to_date() {
        let committed = include_str!("../generated/format-id.js");
        assert_eq!(
            committed,
            emit_javascript(),
            "crates/phx_format_id/generated/format-id.js is stale — regenerate with \
             `cargo run -p phx_format_id --example emit_js > crates/phx_format_id/generated/format-id.js` \
             and copy it to site/assets/zip-checker/format-id.js"
        );
    }

    #[test]
    fn every_signature_identifies_its_own_format() {
        for s in SIGNATURES {
            let bytes = specimen_for(s);
            assert_eq!(
                identify(Bytes::whole(&bytes)),
                Some(s.format),
                "{:?} at {:?}",
                s.format,
                s.anchor
            );
        }
    }

    /// The end-anchored rules must actually be end-anchored: the same magic placed anywhere
    /// else in a file of the same length must not match. Without this, `End(n)` could be
    /// implemented as a scan and every test above would still pass.
    #[test]
    fn an_end_anchored_magic_does_not_match_elsewhere() {
        let end_rules: Vec<_> = SIGNATURES
            .iter()
            .filter(|s| matches!(s.anchor, Anchor::End(_)))
            .collect();
        assert!(
            !end_rules.is_empty(),
            "the anchor under test must be in use"
        );

        for s in end_rules {
            let good = specimen_for(s);
            assert_eq!(identify(Bytes::whole(&good)), Some(s.format));

            // Same length, same bytes, moved one byte off the anchor.
            let Anchor::End(back) = s.anchor else {
                unreachable!()
            };
            let at = good.len() - back;
            let mut moved = vec![0u8; good.len()];
            moved[at - 1..at - 1 + s.magic.len()].copy_from_slice(s.magic);
            assert_ne!(
                identify(Bytes::whole(&moved)),
                Some(s.format),
                "{:?} matched one byte off its anchor — the rule is not really end-anchored",
                s.format
            );
        }
    }

    /// A tail that was never read cannot be matched against. Passing an empty tail must
    /// silence every end-anchored rule rather than reach into the head by accident.
    #[test]
    fn an_unread_tail_silences_end_anchored_rules() {
        for s in SIGNATURES
            .iter()
            .filter(|s| matches!(s.anchor, Anchor::End(_)))
        {
            let full = specimen_for(s);
            let bytes = Bytes {
                head: &full,
                tail: &[],
                total_len: full.len() as u64,
            };
            assert_ne!(identify(bytes), Some(s.format), "{:?}", s.format);
        }
    }

    #[test]
    fn a_file_one_byte_too_short_declines_rather_than_guesses() {
        for s in SIGNATURES {
            let bytes = specimen_for(s);
            let short = &bytes[..bytes.len() - 1];
            // It may still match an earlier rule, but it must never claim THIS format on
            // bytes that were not there to be read.
            assert_ne!(
                identify(Bytes::whole(short)),
                Some(s.format),
                "{:?} short",
                s.format
            );
        }
    }

    /// Every rule must be able to say where its bytes came from. This is the guard against
    /// the failure this crate exists to prevent — a signature copied from somewhere, by
    /// someone, at some point, that nobody can now check.
    #[test]
    fn every_signature_can_account_for_itself() {
        for s in SIGNATURES {
            match s.provenance {
                Provenance::Measured { specimen } => {
                    assert!(!specimen.is_empty(), "{:?} measured, no specimen", s.format)
                }
                Provenance::Documented { source, .. } => {
                    assert!(!source.is_empty(), "{:?} documented, no source", s.format)
                }
            }
        }
        // And the split must be visible, not collapsed: this table is deliberately both.
        assert!(SIGNATURES.iter().any(|s| s.provenance.is_measured()));
        assert!(SIGNATURES.iter().any(|s| !s.provenance.is_measured()));
    }

    /// A documented signature must never be reported as a measured one, all the way out to
    /// the caller.
    #[test]
    fn provenance_survives_to_the_answer() {
        let vhdx = SIGNATURES
            .iter()
            .find(|s| s.format == Format::Vhdx)
            .expect("VHDX is in the table");
        let bytes = specimen_for(vhdx);
        let id = Identification::of(Bytes::whole(&bytes), "disk.vhdx");
        assert_eq!(id.by_content, Some(Format::Vhdx));
        assert_eq!(id.provenance, Some(vhdx.provenance));
        assert!(
            !id.provenance.unwrap().is_measured(),
            "no specimen was ever available for VHDX here — saying otherwise would be the lie \
             this whole arrangement exists to prevent"
        );
    }

    #[test]
    fn every_format_is_listed_and_has_a_signature() {
        assert_eq!(FORMATS.len(), 21);
        for f in FORMATS {
            assert!(
                SIGNATURES.iter().any(|s| s.format == *f),
                "{f:?} has no signature"
            );
            assert!(!f.extensions().is_empty(), "{f:?} has no extensions");
            assert!(!f.label().is_empty());
        }
    }

    #[test]
    fn the_two_bounded_reads_cover_every_rule() {
        let widest_head = SIGNATURES
            .iter()
            .filter_map(|s| match s.anchor {
                Anchor::Start(at) => Some(at + s.magic.len()),
                Anchor::End(_) => None,
            })
            .max()
            .unwrap();
        assert!(REQUIRED_PREFIX >= widest_head);

        let deepest_tail = SIGNATURES
            .iter()
            .filter_map(|s| match s.anchor {
                Anchor::End(back) => Some(back),
                Anchor::Start(_) => None,
            })
            .max()
            .unwrap();
        assert_eq!(REQUIRED_SUFFIX, deepest_tail);
    }

    #[test]
    fn unknown_bytes_are_unknown_not_raw_guesses() {
        assert_eq!(identify(Bytes::whole(&[0xDE, 0xAD, 0xBE, 0xEF])), None);
        assert_eq!(identify(Bytes::whole(&[])), None);
    }

    #[test]
    fn the_longest_extension_wins() {
        assert_eq!(from_extension("backup.sqlite3"), Some(Format::Sqlite));
        assert_eq!(from_extension("backup.sqlite"), Some(Format::Sqlite));
        assert_eq!(from_extension("ARCHIVE.ZIP"), Some(Format::Zip));
        assert_eq!(from_extension("no-extension"), None);
    }

    /// The distinction the whole crate is for: a renamed file and a damaged one look the
    /// same to a detector that folds name into content, and they need opposite advice.
    #[test]
    fn content_and_name_disagreements_are_each_their_own_answer() {
        let rar = {
            let mut v = vec![0u8; 7];
            v[..6].copy_from_slice(&[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07]);
            v
        };
        let id = Identification::of(Bytes::whole(&rar), "archive.zip");
        assert_eq!(id.agreement(), Agreement::Mismatch);
        assert_eq!(id.by_content, Some(Format::Rar));
        assert_eq!(id.best_effort(), Some(Format::Rar), "content always wins");

        let damaged = Identification::of(Bytes::whole(&[0u8; 64]), "archive.zip");
        assert_eq!(damaged.agreement(), Agreement::NameOnly);
        assert_eq!(damaged.by_content, None);
        assert_eq!(
            damaged.provenance, None,
            "a non-answer has no provenance to report"
        );

        let unnamed = Identification::of(Bytes::whole(&rar), "data");
        assert_eq!(unnamed.agreement(), Agreement::ContentOnly);

        let nothing = Identification::of(Bytes::whole(&[0xDE, 0xAD]), "data");
        assert_eq!(nothing.agreement(), Agreement::Unknown);
        assert_eq!(nothing.best_effort(), None);
    }
}
