//! Named CRC variants — **real, format-relevant** parameter sets only (no
//! speculative catalogue). Each is the checksum a supported format actually
//! carries, so a reverify against it is genuine independent evidence (§1.1).

use super::CrcParams;

/// CRC-32/ISO-HDLC — the zlib / PKZIP CRC-32 used by **ZIP, GZIP, and PNG**
/// (per-chunk over raw bytes). Catalogue check value (`"123456789"`) =
/// `0xCBF43926`.
pub const CRC32_ISO_HDLC: CrcParams = CrcParams {
    width: 32,
    poly: 0x04C1_1DB7,
    init: 0xFFFF_FFFF,
    refin: true,
    refout: true,
    xorout: 0xFFFF_FFFF,
    name: "CRC-32/ISO-HDLC",
};

/// CRC-32/BZIP2 — the per-block CRC bzip2 computes over **uncompressed** block
/// data (MSB-first, *unreflected* — distinct from CRC-32/ISO-HDLC). Catalogue
/// check value (`"123456789"`) = `0xFC891918`.
pub const CRC32_BZIP2: CrcParams = CrcParams {
    width: 32,
    poly: 0x04C1_1DB7,
    init: 0xFFFF_FFFF,
    refin: false,
    refout: false,
    xorout: 0xFFFF_FFFF,
    name: "CRC-32/BZIP2",
};

/// CRC-64/XZ — the `.xz` block / stream check (one of XZ's check modes).
/// Catalogue check value (`"123456789"`) = `0x995DC9BBDF1939FA`.
pub const CRC64_XZ: CrcParams = CrcParams {
    width: 64,
    poly: 0x42F0_E1EB_A9EA_3693,
    init: 0xFFFF_FFFF_FFFF_FFFF,
    refin: true,
    refout: true,
    xorout: 0xFFFF_FFFF_FFFF_FFFF,
    name: "CRC-64/XZ",
};
