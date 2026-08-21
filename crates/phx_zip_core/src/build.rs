//! Deterministic ZIP / OPC fixture encoder.
//!
//! Builds valid ZIP containers and minimal OOXML (OPC) packages so tests and the
//! OPC benchmark have exact ground truth and can inject precise damage — without
//! committing binaries or depending on an external zip tool. Inverse of the
//! [`super::zip`] reader, so a round-trip validates both. Fixtures only.

use std::io::Write;

const LFH_SIG: u32 = 0x0403_4b50;
const CDFH_SIG: u32 = 0x0201_4b50;
const EOCD_SIG: u32 = 0x0605_4b50;
const DD_SIG: u32 = 0x0807_4b50; // data descriptor "PK\x07\x08"

fn crc32(bytes: &[u8]) -> u32 {
    let mut c = flate2::Crc::new();
    c.update(bytes);
    c.sum()
}

fn deflate(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    let _ = e.write_all(data);
    e.finish().unwrap_or_default()
}

/// Build a valid ZIP from `(name, data)` parts. Each part is DEFLATE-compressed
/// when that is strictly smaller, else stored — exactly as a real zipper does.
pub fn encode_zip(parts: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    // (name, method, crc, comp_size, uncomp_size, local_header_offset)
    let mut cd_records: Vec<(String, u16, u32, u32, u32, u32)> = Vec::new();

    for (name, data) in parts {
        let crc = crc32(data);
        let deflated = deflate(data);
        let (method, payload): (u16, Vec<u8>) = if deflated.len() < data.len() {
            (8, deflated)
        } else {
            (0, data.to_vec())
        };
        let lho = out.len() as u32;
        cd_records.push((
            (*name).to_string(),
            method,
            crc,
            payload.len() as u32,
            data.len() as u32,
            lho,
        ));

        // Local file header.
        out.extend_from_slice(&LFH_SIG.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&method.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // mod time
        out.extend_from_slice(&0u16.to_le_bytes()); // mod date
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&payload);
    }

    // Central directory.
    let cd_offset = out.len() as u32;
    let mut cd = Vec::new();
    for (name, method, crc, comp, uncomp, lho) in &cd_records {
        cd.extend_from_slice(&CDFH_SIG.to_le_bytes());
        cd.extend_from_slice(&20u16.to_le_bytes()); // version made by
        cd.extend_from_slice(&20u16.to_le_bytes()); // version needed
        cd.extend_from_slice(&0u16.to_le_bytes()); // flags
        cd.extend_from_slice(&method.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes()); // mod time
        cd.extend_from_slice(&0u16.to_le_bytes()); // mod date
        cd.extend_from_slice(&crc.to_le_bytes());
        cd.extend_from_slice(&comp.to_le_bytes());
        cd.extend_from_slice(&uncomp.to_le_bytes());
        cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes()); // extra len
        cd.extend_from_slice(&0u16.to_le_bytes()); // comment len
        cd.extend_from_slice(&0u16.to_le_bytes()); // disk start
        cd.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        cd.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        cd.extend_from_slice(&lho.to_le_bytes());
        cd.extend_from_slice(name.as_bytes());
    }
    let cd_size = cd.len() as u32;
    out.extend_from_slice(&cd);

    // End of central directory.
    out.extend_from_slice(&EOCD_SIG.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // disk number
    out.extend_from_slice(&0u16.to_le_bytes()); // cd start disk
    out.extend_from_slice(&(cd_records.len() as u16).to_le_bytes()); // entries this disk
    out.extend_from_slice(&(cd_records.len() as u16).to_le_bytes()); // entries total
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len
    out
}

/// Build a ZIP whose every entry is written **streaming** (general-purpose bit 3):
/// the local header carries zero CRC/sizes, the true values follow in a data
/// descriptor, and the central directory is authoritative. Used to exercise
/// data-descriptor handling (works with the CD; abstains on a CD-less local scan).
pub fn encode_zip_streamed(parts: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cd_records: Vec<(String, u16, u32, u32, u32, u32)> = Vec::new();

    for (name, data) in parts {
        let crc = crc32(data);
        let deflated = deflate(data);
        let (method, payload): (u16, Vec<u8>) = if deflated.len() < data.len() {
            (8, deflated)
        } else {
            (0, data.to_vec())
        };
        let lho = out.len() as u32;
        cd_records.push((
            (*name).to_string(),
            method,
            crc,
            payload.len() as u32,
            data.len() as u32,
            lho,
        ));

        // Local file header — bit 3 set; CRC + sizes left zero (streaming).
        out.extend_from_slice(&LFH_SIG.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0x0008u16.to_le_bytes()); // flags: data descriptor
        out.extend_from_slice(&method.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // crc (in descriptor)
        out.extend_from_slice(&0u32.to_le_bytes()); // comp size (in descriptor)
        out.extend_from_slice(&0u32.to_le_bytes()); // uncomp size (in descriptor)
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&payload);
        // Trailing data descriptor.
        out.extend_from_slice(&DD_SIG.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    }

    let cd_offset = out.len() as u32;
    let mut cd = Vec::new();
    for (name, method, crc, comp, uncomp, lho) in &cd_records {
        cd.extend_from_slice(&CDFH_SIG.to_le_bytes());
        cd.extend_from_slice(&20u16.to_le_bytes());
        cd.extend_from_slice(&20u16.to_le_bytes());
        cd.extend_from_slice(&0x0008u16.to_le_bytes()); // flags: data descriptor
        cd.extend_from_slice(&method.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&crc.to_le_bytes());
        cd.extend_from_slice(&comp.to_le_bytes());
        cd.extend_from_slice(&uncomp.to_le_bytes());
        cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u32.to_le_bytes());
        cd.extend_from_slice(&lho.to_le_bytes());
        cd.extend_from_slice(name.as_bytes());
    }
    let cd_size = cd.len() as u32;
    out.extend_from_slice(&cd);

    out.extend_from_slice(&EOCD_SIG.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(cd_records.len() as u16).to_le_bytes());
    out.extend_from_slice(&(cd_records.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

// ── OPC / OOXML package fixtures ───────────────────────────────────────────────

const CT_NS: &str = "http://schemas.openxmlformats.org/package/2006/content-types";
const REL_NS: &str = "http://schemas.openxmlformats.org/package/2006/relationships";
const OFFICE_DOC_REL: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument";
const WORKSHEET_REL: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet";
const SLIDE_REL: &str = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide";
const WORD_MAIN_CT: &str =
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml";
const XLSX_MAIN_CT: &str =
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml";
const XLSX_SHEET_CT: &str =
    "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml";
const PPTX_MAIN_CT: &str =
    "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml";
const PPTX_SLIDE_CT: &str =
    "application/vnd.openxmlformats-officedocument.presentationml.slide+xml";

fn xml_header() -> &'static str {
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
}

/// The canonical parts of a minimal valid `.docx` (OPC) package, in package
/// order. Callers may drop/replace/duplicate entries to craft damage fixtures.
pub fn docx_parts() -> Vec<(String, Vec<u8>)> {
    let content_types = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<Types xmlns=\"{CT_NS}\">\
<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\
<Default Extension=\"xml\" ContentType=\"application/xml\"/>\
<Override PartName=\"/word/document.xml\" ContentType=\"{WORD_MAIN_CT}\"/>\
</Types>"
    );
    let root_rels = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<Relationships xmlns=\"{REL_NS}\">\
<Relationship Id=\"rId1\" Type=\"{OFFICE_DOC_REL}\" Target=\"word/document.xml\"/>\
</Relationships>"
    );
    let document = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">\
<w:body><w:p><w:r><w:t>Hello, PHX semantic recovery.</w:t></w:r></w:p></w:body>\
</w:document>";

    vec![
        (
            "[Content_Types].xml".to_string(),
            content_types.into_bytes(),
        ),
        ("_rels/.rels".to_string(), root_rels.into_bytes()),
        (
            "word/document.xml".to_string(),
            document.as_bytes().to_vec(),
        ),
    ]
}

/// Convenience: encode the canonical minimal `.docx`.
pub fn encode_docx() -> Vec<u8> {
    encode_parts(&docx_parts())
}

/// The canonical parts of a minimal valid `.xlsx` (OPC) package.
pub fn xlsx_parts() -> Vec<(String, Vec<u8>)> {
    let h = xml_header();
    let content_types = format!(
        "{h}<Types xmlns=\"{CT_NS}\">\
<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\
<Default Extension=\"xml\" ContentType=\"application/xml\"/>\
<Override PartName=\"/xl/workbook.xml\" ContentType=\"{XLSX_MAIN_CT}\"/>\
<Override PartName=\"/xl/worksheets/sheet1.xml\" ContentType=\"{XLSX_SHEET_CT}\"/>\
</Types>"
    );
    let root_rels = format!(
        "{h}<Relationships xmlns=\"{REL_NS}\">\
<Relationship Id=\"rId1\" Type=\"{OFFICE_DOC_REL}\" Target=\"xl/workbook.xml\"/>\
</Relationships>"
    );
    let workbook = format!(
        "{h}<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">\
<sheets><sheet name=\"Sheet1\" sheetId=\"1\" r:id=\"rId1\" \
xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"/></sheets>\
</workbook>"
    );
    let workbook_rels = format!(
        "{h}<Relationships xmlns=\"{REL_NS}\">\
<Relationship Id=\"rId1\" Type=\"{WORKSHEET_REL}\" Target=\"worksheets/sheet1.xml\"/>\
</Relationships>"
    );
    let sheet1 = format!(
        "{h}<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">\
<sheetData><row r=\"1\"><c r=\"A1\" t=\"inlineStr\"><is><t>PHX</t></is></c></row></sheetData>\
</worksheet>"
    );
    vec![
        ("[Content_Types].xml".into(), content_types.into_bytes()),
        ("_rels/.rels".into(), root_rels.into_bytes()),
        ("xl/workbook.xml".into(), workbook.into_bytes()),
        (
            "xl/_rels/workbook.xml.rels".into(),
            workbook_rels.into_bytes(),
        ),
        ("xl/worksheets/sheet1.xml".into(), sheet1.into_bytes()),
    ]
}

/// Convenience: encode the canonical minimal `.xlsx`.
pub fn encode_xlsx() -> Vec<u8> {
    encode_parts(&xlsx_parts())
}

/// The canonical parts of a minimal valid `.pptx` (OPC) package.
pub fn pptx_parts() -> Vec<(String, Vec<u8>)> {
    let h = xml_header();
    let content_types = format!(
        "{h}<Types xmlns=\"{CT_NS}\">\
<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\
<Default Extension=\"xml\" ContentType=\"application/xml\"/>\
<Override PartName=\"/ppt/presentation.xml\" ContentType=\"{PPTX_MAIN_CT}\"/>\
<Override PartName=\"/ppt/slides/slide1.xml\" ContentType=\"{PPTX_SLIDE_CT}\"/>\
</Types>"
    );
    let root_rels = format!(
        "{h}<Relationships xmlns=\"{REL_NS}\">\
<Relationship Id=\"rId1\" Type=\"{OFFICE_DOC_REL}\" Target=\"ppt/presentation.xml\"/>\
</Relationships>"
    );
    let presentation = format!(
        "{h}<p:presentation xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\" \
xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\">\
<p:sldIdLst><p:sldId id=\"256\" r:id=\"rId1\"/></p:sldIdLst></p:presentation>"
    );
    let presentation_rels = format!(
        "{h}<Relationships xmlns=\"{REL_NS}\">\
<Relationship Id=\"rId1\" Type=\"{SLIDE_REL}\" Target=\"slides/slide1.xml\"/>\
</Relationships>"
    );
    let slide1 = format!(
        "{h}<p:sld xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\">\
<p:cSld><p:spTree/></p:cSld></p:sld>"
    );
    vec![
        ("[Content_Types].xml".into(), content_types.into_bytes()),
        ("_rels/.rels".into(), root_rels.into_bytes()),
        ("ppt/presentation.xml".into(), presentation.into_bytes()),
        (
            "ppt/_rels/presentation.xml.rels".into(),
            presentation_rels.into_bytes(),
        ),
        ("ppt/slides/slide1.xml".into(), slide1.into_bytes()),
    ]
}

/// Convenience: encode the canonical minimal `.pptx`.
pub fn encode_pptx() -> Vec<u8> {
    encode_parts(&pptx_parts())
}

/// Encode owned `(name, data)` parts into a ZIP (borrow-shim around [`encode_zip`]).
pub fn encode_parts(parts: &[(String, Vec<u8>)]) -> Vec<u8> {
    let refs: Vec<(&str, &[u8])> = parts
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect();
    encode_zip(&refs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opc_zip::{extract_entry, parse_zip, ExtractStatus};

    #[test]
    fn docx_roundtrips_all_parts_verified() {
        let zip = encode_docx();
        let parsed = parse_zip(&zip);
        assert_eq!(parsed.entries.len(), 3);
        for e in &parsed.entries {
            assert_eq!(extract_entry(&zip, e).status, ExtractStatus::VerifiedCrc);
        }
    }

    #[test]
    fn xlsx_and_pptx_roundtrip_all_parts_verified() {
        for zip in [encode_xlsx(), encode_pptx()] {
            let parsed = parse_zip(&zip);
            assert_eq!(parsed.entries.len(), 5);
            for e in &parsed.entries {
                assert_eq!(extract_entry(&zip, e).status, ExtractStatus::VerifiedCrc);
            }
        }
    }

    #[test]
    fn streamed_entries_verify_when_central_dir_present() {
        // Data-descriptor entries: local sizes are zero, CD is authoritative.
        let parts = docx_parts();
        let refs: Vec<(&str, &[u8])> = parts
            .iter()
            .map(|(n, d)| (n.as_str(), d.as_slice()))
            .collect();
        let zip = encode_zip_streamed(&refs);
        let parsed = parse_zip(&zip);
        assert!(parsed.cd_found);
        for e in &parsed.entries {
            assert!(e.has_data_descriptor());
            assert_eq!(extract_entry(&zip, e).status, ExtractStatus::VerifiedCrc);
        }
    }
}
