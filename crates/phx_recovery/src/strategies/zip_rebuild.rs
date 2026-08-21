//! `ZipCentralDirectoryRebuild` — reconstruct a ZIP central directory and EOCD
//! from the surviving local file headers.
//!
//! This is a genuine repair: it walks the local file headers (`PK\x03\x04`),
//! rebuilds a central directory pointing at them, and appends a fresh EOCD.
//! Member *data* is copied verbatim — never re-compressed or altered.

use phx_analyze_engine::model::{AnalysisResult, ArchiveFormat, Corruption, CorruptionCategory};
use phx_analyze_engine::reader::DataSource;

use crate::model::{DataSink, RecoveryError, RecoveryReport};
use crate::plan::RepairRisk;

use super::{read_all, RecoveryStrategy};

const LFH_SIG: u32 = 0x0403_4b50;
const CDFH_SIG: u32 = 0x0201_4b50;
const EOCD_SIG: u32 = 0x0605_4b50;

/// Rebuild a damaged/missing ZIP central directory.
pub struct ZipCentralDirectoryRebuild;

impl RecoveryStrategy for ZipCentralDirectoryRebuild {
    fn name(&self) -> &str {
        "zip-rebuild"
    }

    fn technique(&self) -> &'static str {
        "CentralDirRebuild"
    }

    fn risk(&self) -> RepairRisk {
        // Rebuilds the directory from intact local headers; member payloads are
        // copied verbatim, so the result is byte-exact for surviving members.
        RepairRisk::Safe
    }

    fn handles(&self, c: &Corruption) -> bool {
        let id = &c.chain.primary.rule_id;
        id.starts_with("ZIP_EOCD") || id.starts_with("ZIP_CD") || id.starts_with("ZIP_LFH")
    }

    fn predicted_outcome(&self, _c: &Corruption) -> String {
        "rebuild the central directory and EOCD from surviving local headers".to_string()
    }

    fn can_apply(&self, result: &AnalysisResult) -> bool {
        result.archive_format == Some(ArchiveFormat::Zip)
            && result.corruptions.iter().any(|c| {
                c.category == CorruptionCategory::StructuralCorruption
                    || c.chain.primary.rule_id.starts_with("ZIP_CD")
                    || c.chain.primary.rule_id.starts_with("ZIP_EOCD")
                    || c.chain.primary.rule_id.starts_with("ZIP_LFH")
            })
    }

    fn priority(&self) -> u8 {
        80
    }

    fn apply(
        &self,
        source: &DataSource,
        output: &mut DataSink,
    ) -> Result<RecoveryReport, RecoveryError> {
        let data = read_all(source)?;
        let mut report = RecoveryReport::empty(Default::default());
        report.strategies_applied.push(self.name().to_string());

        let headers = scan_local_headers(&data);
        if headers.is_empty() {
            report
                .warnings
                .push("no recoverable local file headers found".to_string());
            report.success = false;
            return Ok(report);
        }

        // Data region ends after the last member's payload.
        let data_end = headers
            .iter()
            .map(|h| h.data_offset + h.comp_size)
            .max()
            .unwrap_or(0)
            .min(data.len());

        output.write(&data[..data_end]);

        // Build and append the central directory.
        let cd_offset = data_end as u32;
        let mut cd = Vec::new();
        for h in &headers {
            cd.extend_from_slice(&CDFH_SIG.to_le_bytes());
            cd.extend_from_slice(&20u16.to_le_bytes()); // version made by
            cd.extend_from_slice(&h.version_needed.to_le_bytes());
            cd.extend_from_slice(&h.flags.to_le_bytes());
            cd.extend_from_slice(&h.method.to_le_bytes());
            cd.extend_from_slice(&h.mod_time.to_le_bytes());
            cd.extend_from_slice(&h.mod_date.to_le_bytes());
            cd.extend_from_slice(&h.crc32.to_le_bytes());
            cd.extend_from_slice(&h.comp_size32().to_le_bytes());
            cd.extend_from_slice(&h.uncomp_size32().to_le_bytes());
            cd.extend_from_slice(&(h.name.len() as u16).to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes()); // extra len
            cd.extend_from_slice(&0u16.to_le_bytes()); // comment len
            cd.extend_from_slice(&0u16.to_le_bytes()); // disk start
            cd.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
            cd.extend_from_slice(&0u32.to_le_bytes()); // external attrs
            cd.extend_from_slice(&(h.lfh_offset as u32).to_le_bytes());
            cd.extend_from_slice(&h.name);
            report
                .files_recovered
                .push(String::from_utf8_lossy(&h.name).into_owned().into());
        }

        let cd_size = cd.len() as u32;
        output.write(&cd);

        // Append the EOCD.
        let mut eocd = Vec::with_capacity(22);
        eocd.extend_from_slice(&EOCD_SIG.to_le_bytes());
        eocd.extend_from_slice(&0u16.to_le_bytes()); // disk
        eocd.extend_from_slice(&0u16.to_le_bytes()); // disk w/ cd
        eocd.extend_from_slice(&(headers.len() as u16).to_le_bytes());
        eocd.extend_from_slice(&(headers.len() as u16).to_le_bytes());
        eocd.extend_from_slice(&cd_size.to_le_bytes());
        eocd.extend_from_slice(&cd_offset.to_le_bytes());
        eocd.extend_from_slice(&0u16.to_le_bytes()); // comment len
        output.write(&eocd);

        report.bytes_recovered = output.len();
        report.success = true;
        report.warnings.push(format!(
            "rebuilt central directory for {} member(s) from local headers",
            headers.len()
        ));
        Ok(report)
    }
}

/// A parsed local file header.
struct LocalHeader {
    lfh_offset: usize,
    version_needed: u16,
    flags: u16,
    method: u16,
    mod_time: u16,
    mod_date: u16,
    crc32: u32,
    comp_size: usize,
    uncomp_size: usize,
    data_offset: usize,
    name: Vec<u8>,
}

impl LocalHeader {
    fn comp_size32(&self) -> u32 {
        self.comp_size as u32
    }
    fn uncomp_size32(&self) -> u32 {
        self.uncomp_size as u32
    }
}

/// Walk local file headers from the start of the stream. Stops at the first
/// header that cannot be parsed (e.g. a streamed entry with a data descriptor
/// and zero sizes, which cannot be traversed without the central directory).
fn scan_local_headers(data: &[u8]) -> Vec<LocalHeader> {
    let mut headers = Vec::new();
    let mut pos = 0usize;
    while pos + 30 <= data.len() {
        if u32_le(&data[pos..pos + 4]) != LFH_SIG {
            break;
        }
        let flags = u16_le(&data[pos + 6..pos + 8]);
        let method = u16_le(&data[pos + 8..pos + 10]);
        let mod_time = u16_le(&data[pos + 10..pos + 12]);
        let mod_date = u16_le(&data[pos + 12..pos + 14]);
        let crc32 = u32_le(&data[pos + 14..pos + 18]);
        let comp_size = u32_le(&data[pos + 18..pos + 22]) as usize;
        let uncomp_size = u32_le(&data[pos + 22..pos + 26]) as usize;
        let name_len = u16_le(&data[pos + 26..pos + 28]) as usize;
        let extra_len = u16_le(&data[pos + 28..pos + 30]) as usize;

        let name_start = pos + 30;
        let name_end = name_start + name_len;
        if name_end + extra_len > data.len() {
            break;
        }
        let name = data[name_start..name_end].to_vec();
        let data_offset = name_end + extra_len;

        // Streamed entries (bit 3) without sizes cannot be traversed reliably.
        if flags & 0x0008 != 0 && comp_size == 0 {
            break;
        }
        if data_offset + comp_size > data.len() {
            break;
        }

        headers.push(LocalHeader {
            lfh_offset: pos,
            version_needed: u16_le(&data[pos + 4..pos + 6]),
            flags,
            method,
            mod_time,
            mod_date,
            crc32,
            comp_size,
            uncomp_size,
            data_offset,
            name,
        });

        pos = data_offset + comp_size;
    }
    headers
}

#[inline]
fn u16_le(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}
#[inline]
fn u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}
