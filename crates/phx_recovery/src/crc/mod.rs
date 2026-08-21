//! Parameterized CRC engine (Rocksoft model) — forward compute + independent
//! **reverify**. This is the EXP-0-justified subset of `PROOF_CARRYING_RECOVERY.md`
//! §6: the *independent verifier* that the GO tracks (EXP-PDS / EXP-IFM /
//! EXP-EC) rely on to count `evidence_bits` (see [`crate::evidence`]).
//!
//! **Deferred (NOT built here):** the GF(2) linear-map pieces `homogeneous_crc`
//! and `L(eᵢ)` columns, and the `gf2` module — they exist only to *solve* a CRC
//! (VCSR), and EXP-0 ruled the VCSR family **NO-GO**. They enter only when a
//! GF(2)-solving track clears its gate (VR-7: do not build a solver the surface
//! does not justify). This module computes and checks CRCs; it never solves them.
//!
//! Clean-room, dependency-free. Cross-checked against `crc32fast` in dev-tests
//! only (no production dependency).

pub mod catalog;

/// Rocksoft CRC parameters (`width` in `1..=64`).
///
/// The model is the standard reflected/non-reflected bit-at-a-time algorithm:
/// optionally reflect each input byte, process MSB-first against `poly`,
/// optionally reflect the final register, then XOR `xorout`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrcParams {
    pub width: u8,
    pub poly: u64,
    pub init: u64,
    pub refin: bool,
    pub refout: bool,
    pub xorout: u64,
    /// Human name, e.g. `"CRC-32/ISO-HDLC"`. Carried into evidence records.
    pub name: &'static str,
}

#[inline]
fn reflect(value: u64, width: u32) -> u64 {
    value.reverse_bits() >> (64 - width)
}

impl CrcParams {
    /// Low `width` bits all set.
    #[inline]
    pub const fn mask(&self) -> u64 {
        if self.width >= 64 {
            u64::MAX
        } else {
            (1u64 << self.width) - 1
        }
    }

    /// Forward CRC over `data`.
    pub fn checksum(&self, data: &[u8]) -> u64 {
        let width = self.width as u32;
        let mask = self.mask();
        let topbit = 1u64 << (width - 1);
        let mut reg = self.init & mask;
        for &byte in data {
            let b = if self.refin {
                (byte.reverse_bits()) as u64
            } else {
                byte as u64
            };
            reg ^= (b << (width - 8)) & mask;
            for _ in 0..8 {
                reg = if reg & topbit != 0 {
                    ((reg << 1) ^ self.poly) & mask
                } else {
                    (reg << 1) & mask
                };
            }
        }
        if self.refout {
            reg = reflect(reg, width);
        }
        (reg ^ self.xorout) & mask
    }

    /// **Independent reverify** (VR-1): does the stored value match the CRC
    /// recomputed over `data`?
    ///
    /// This is *independent evidence* **only** when the CRC was not used to
    /// generate `data` — the tautology rule (a checksum solved-against
    /// contributes 0 bits) is enforced in [`crate::evidence`], not here.
    pub fn verify(&self, data: &[u8], stored: u64) -> bool {
        self.checksum(data) == (stored & self.mask())
    }

    /// Bits of false-accept protection a single pass of this CRC provides
    /// (= its width). Used to populate an evidence `Verifier`.
    #[inline]
    pub const fn evidence_width(&self) -> u32 {
        self.width as u32
    }
}

#[cfg(test)]
mod tests {
    use super::catalog::{CRC32_BZIP2, CRC32_ISO_HDLC, CRC64_XZ};

    /// Deterministic pseudo-bytes for cross-checks (no RNG dependency).
    fn pseudo(seed: u64, n: usize) -> Vec<u8> {
        let mut s = seed ^ 0x9E37_79B9_7F4A_7C15;
        (0..n)
            .map(|_| {
                s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut z = s;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                (z ^ (z >> 31)) as u8
            })
            .collect()
    }

    #[test]
    fn crc32_rocksoft_check_vector() {
        // Catalogued check value of "123456789" for CRC-32/ISO-HDLC.
        assert_eq!(CRC32_ISO_HDLC.checksum(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn crc64_xz_rocksoft_check_vector() {
        assert_eq!(CRC64_XZ.checksum(b"123456789"), 0x995D_C9BB_DF19_39FA);
    }

    #[test]
    fn crc32_bzip2_rocksoft_check_vector() {
        // Unreflected CRC-32 (bzip2 block CRC) — distinct from ISO-HDLC.
        assert_eq!(CRC32_BZIP2.checksum(b"123456789"), 0xFC89_1918);
    }

    #[test]
    fn empty_input_is_zero_for_both() {
        assert_eq!(CRC32_ISO_HDLC.checksum(b""), 0);
        assert_eq!(CRC64_XZ.checksum(b""), 0);
    }

    #[test]
    fn crc32_matches_reference_crate_crc32fast() {
        // Dev-only cross-check against the external reference crate.
        for seed in 0..64u64 {
            for len in [0usize, 1, 7, 64, 255, 1000] {
                let data = pseudo(seed * 31 + len as u64, len);
                let mut h = crc32fast::Hasher::new();
                h.update(&data);
                assert_eq!(
                    CRC32_ISO_HDLC.checksum(&data) as u32,
                    h.finalize(),
                    "mismatch at seed={seed} len={len}"
                );
            }
        }
    }

    #[test]
    fn verify_accepts_correct_and_rejects_corrupt() {
        let data = pseudo(7, 300);
        let c = CRC32_ISO_HDLC.checksum(&data);
        assert!(CRC32_ISO_HDLC.verify(&data, c));
        assert!(!CRC32_ISO_HDLC.verify(&data, c ^ 1));
        let mut bad = data.clone();
        bad[10] ^= 0x80;
        assert!(!CRC32_ISO_HDLC.verify(&bad, c));
    }

    #[test]
    fn mask_is_width_correct() {
        assert_eq!(CRC32_ISO_HDLC.mask(), 0xFFFF_FFFF);
        assert_eq!(CRC64_XZ.mask(), u64::MAX);
    }

    #[test]
    fn evidence_width_equals_crc_width() {
        assert_eq!(CRC32_ISO_HDLC.evidence_width(), 32);
        assert_eq!(CRC64_XZ.evidence_width(), 64);
    }
}
