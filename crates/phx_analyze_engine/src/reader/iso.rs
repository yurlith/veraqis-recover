//! Read-only ISO 9660 reader.
//!
//! Validates the Primary Volume Descriptor (PVD) at sector 16 and checks the
//! path-table pointer for in-bounds sanity. Full directory-tree walking is out
//! of scope for V1; the detector relies on the structural facts gathered here.

use crate::error::EngineError;
use crate::model::ArchiveFormat;

use super::{ArchiveEntry, ArchiveReader, DataSource};

const SECTOR: u64 = 2048;
/// PVD lives at logical sector 16.
const PVD_OFFSET: u64 = 16 * SECTOR; // 32768
const CD001: &[u8] = b"CD001";

/// Structural facts extracted from an ISO 9660 image.
pub(crate) struct IsoParse {
    /// `true` if a valid PVD (type 1 + "CD001") was found at sector 16.
    pub pvd_present: bool,
    /// Volume size in logical sectors, from the PVD.
    pub volume_space_sectors: u32,
    /// Declared L-path-table size in bytes.
    pub path_table_size: u32,
    /// L-path-table location (logical sector).
    pub path_table_lba: u32,
    /// `true` if the path-table pointer lands inside the declared volume.
    pub path_table_in_bounds: bool,
}

/// Reader for the ISO 9660 format.
pub struct IsoReader;

impl IsoReader {
    pub(crate) fn parse(&self, source: &DataSource) -> IsoParse {
        let mut parse = IsoParse {
            pvd_present: false,
            volume_space_sectors: 0,
            path_table_size: 0,
            path_table_lba: 0,
            path_table_in_bounds: false,
        };

        let pvd = match source.read_exact_at(PVD_OFFSET, SECTOR as usize) {
            Ok(b) => b,
            Err(_) => return parse,
        };

        // Byte 0 = descriptor type (1 = PVD); bytes 1..6 = "CD001".
        parse.pvd_present = pvd[0] == 1 && &pvd[1..6] == CD001;
        if !parse.pvd_present {
            return parse;
        }

        // Volume space size: both-endian u32 at offset 80 (LE half).
        parse.volume_space_sectors = u32_le(&pvd[80..84]);
        // Path table size: both-endian u32 at offset 132 (LE half).
        parse.path_table_size = u32_le(&pvd[132..136]);
        // L-path-table location: LE u32 at offset 140 (in sectors).
        parse.path_table_lba = u32_le(&pvd[140..144]);

        let pt_byte_offset = parse.path_table_lba as u64 * SECTOR;
        parse.path_table_in_bounds = parse.path_table_lba > 0 && pt_byte_offset < source.len();

        parse
    }
}

impl ArchiveReader for IsoReader {
    fn format(&self) -> ArchiveFormat {
        ArchiveFormat::Iso9660
    }

    fn entries(&self, source: &DataSource) -> Result<Vec<ArchiveEntry>, EngineError> {
        // Directory-tree enumeration is not implemented in V1. Represent the
        // image as a single volume-level entry so downstream code is uniform.
        let parse = self.parse(source);
        if !parse.pvd_present {
            return Ok(Vec::new());
        }
        Ok(vec![ArchiveEntry {
            path: std::path::PathBuf::from("[iso-volume]"),
            size: parse.volume_space_sectors as u64 * SECTOR,
            compressed_size: source.len(),
            offset: 0,
            encrypted: false,
            stored_crc32: None,
            is_link: false,
            link_target: None,
        }])
    }
}

#[inline]
fn u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iso_with_pvd() -> Vec<u8> {
        let mut v = vec![0u8; PVD_OFFSET as usize + SECTOR as usize];
        let pvd = PVD_OFFSET as usize;
        v[pvd] = 1;
        v[pvd + 1..pvd + 6].copy_from_slice(CD001);
        // volume space = 20 sectors
        v[pvd + 80..pvd + 84].copy_from_slice(&20u32.to_le_bytes());
        // path table lba = 18
        v[pvd + 140..pvd + 144].copy_from_slice(&18u32.to_le_bytes());
        v
    }

    #[test]
    fn detects_pvd() {
        let src = DataSource::from_bytes("x.iso", iso_with_pvd());
        let parse = IsoReader.parse(&src);
        assert!(parse.pvd_present);
        assert_eq!(parse.volume_space_sectors, 20);
        assert_eq!(parse.path_table_lba, 18);
    }

    #[test]
    fn no_pvd_when_too_small() {
        let src = DataSource::from_bytes("x.iso", vec![0u8; 1024]);
        assert!(!IsoReader.parse(&src).pvd_present);
    }
}
