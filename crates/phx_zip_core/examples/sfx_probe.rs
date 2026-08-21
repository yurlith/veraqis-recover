//! Does a single offset shift distinguish a self-extracting stub from damage?
use phx_zip_core::cd_scan::scan_surviving_cd;

fn mk(stub: usize) -> Vec<u8> {
    let (nb, db) = (b"a.txt".as_slice(), b"hello".as_slice());
    let u16le = |n: u16| n.to_le_bytes().to_vec();
    let u32le = |n: u32| n.to_le_bytes().to_vec();
    let mut v = vec![0x4du8; stub];
    let mut body = vec![];
    body.extend(u32le(0x04034b50));
    body.extend(u16le(20));
    body.extend(u16le(0));
    body.extend(u16le(0));
    body.extend(u16le(0));
    body.extend(u16le(0));
    body.extend(u32le(0));
    body.extend(u32le(db.len() as u32));
    body.extend(u32le(db.len() as u32));
    body.extend(u16le(nb.len() as u16));
    body.extend(u16le(0));
    body.extend_from_slice(nb);
    body.extend_from_slice(db);
    let body_at = v.len();
    v.extend_from_slice(&body);
    let cd_at = v.len();
    let mut cd = vec![];
    cd.extend(u32le(0x02014b50));
    cd.extend(u16le(20));
    cd.extend(u16le(20));
    for _ in 0..4 {
        cd.extend(u16le(0));
    }
    cd.extend(u32le(0));
    cd.extend(u32le(db.len() as u32));
    cd.extend(u32le(db.len() as u32));
    cd.extend(u16le(nb.len() as u16));
    for _ in 0..4 {
        cd.extend(u16le(0));
    }
    cd.extend(u32le(0));
    cd.extend(u32le((body_at - stub) as u32)); // offset as it was BEFORE the stub
    cd.extend_from_slice(nb);
    v.extend_from_slice(&cd);
    v.extend(u32le(0x06054b50));
    v.extend(u16le(0));
    v.extend(u16le(0));
    v.extend(u16le(1));
    v.extend(u16le(1));
    v.extend(u32le(cd.len() as u32));
    v.extend(u32le(cd_at as u32));
    v.extend(u16le(0));
    v
}

fn main() {
    for (label, bytes) in [("plain (no stub)", mk(0)), ("SFX stub 512 B", mk(512))] {
        let r = scan_surviving_cd(&bytes);
        match r.accepted_candidate() {
            Some(c) => println!(
                "{label:16} records={} supported={} conflicting={} delta={:?} rejection={:?}",
                c.record_count, c.supported, c.conflicting, c.accepted_delta, c.rejection
            ),
            None => println!("{label:16} no candidate accepted"),
        }
    }
}
