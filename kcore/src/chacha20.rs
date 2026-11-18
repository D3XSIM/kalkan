//! ChaCha20 (RFC 8439) and a fast-key-erasure CSPRNG.
//!
//! The kernel random number generator is seeded from the CPU's hardware entropy
//! sources (`RDSEED`, `RDRAND`) mixed with timing jitter, and then expanded with
//! ChaCha20 using Bernstein's *fast key erasure* construction: every request first
//! generates a fresh key from the keystream and immediately overwrites the old one.
//! A later compromise of kernel memory therefore cannot be used to reconstruct
//! random numbers that were handed out earlier (forward secrecy).

const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

#[inline(always)]
fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// The ChaCha20 block function: 64 bytes of keystream.
#[must_use]
pub fn block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let word = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let mut init = [0u32; 16];
    init[..4].copy_from_slice(&CONSTANTS);
    for i in 0..8 {
        init[4 + i] = word(&key[i * 4..]);
    }
    init[12] = counter;
    for i in 0..3 {
        init[13 + i] = word(&nonce[i * 4..]);
    }
    let mut s = init;
    for _ in 0..10 {
        quarter_round(&mut s, 0, 4, 8, 12);
        quarter_round(&mut s, 1, 5, 9, 13);
        quarter_round(&mut s, 2, 6, 10, 14);
        quarter_round(&mut s, 3, 7, 11, 15);
        quarter_round(&mut s, 0, 5, 10, 15);
        quarter_round(&mut s, 1, 6, 11, 12);
        quarter_round(&mut s, 2, 7, 8, 13);
        quarter_round(&mut s, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[i * 4..i * 4 + 4].copy_from_slice(&s[i].wrapping_add(init[i]).to_le_bytes());
    }
    out
}

/// Fast-key-erasure CSPRNG built on ChaCha20.
#[derive(Clone)]
pub struct ChaChaRng {
    key: [u8; 32],
}

impl core::fmt::Debug for ChaChaRng {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print key material.
        f.write_str("ChaChaRng { .. }")
    }
}

impl ChaChaRng {
    /// Creates a generator from a 256-bit seed.
    #[must_use]
    pub const fn from_seed(seed: [u8; 32]) -> Self {
        Self { key: seed }
    }

    /// Mixes additional entropy into the key (the old key is not recoverable from the
    /// new one).
    pub fn reseed(&mut self, entropy: &[u8]) {
        let mut h = crate::blake2b::Blake2b::new();
        h.update(&self.key);
        h.update(entropy);
        let digest = h.finalize();
        self.key.copy_from_slice(&digest[..32]);
    }

    /// Fills `out` with random bytes.
    pub fn fill_bytes(&mut self, out: &mut [u8]) {
        const NONCE: [u8; 12] = [0; 12];
        let mut counter = 0u32;
        // Rekey first: block 0 provides the new key; the old key is overwritten
        // before any output leaves this function.
        let first = block(&self.key, counter, &NONCE);
        let old_key = self.key;
        self.key.copy_from_slice(&first[..32]);
        let mut written = 0;
        let mut ks = [0u8; 64];
        ks[..32].copy_from_slice(&first[32..]);
        let mut avail = 32;
        let mut offset = 0;
        while written < out.len() {
            if avail == 0 {
                counter += 1;
                ks = block(&old_key, counter, &NONCE);
                avail = 64;
                offset = 0;
            }
            let take = avail.min(out.len() - written);
            out[written..written + take].copy_from_slice(&ks[offset..offset + take]);
            written += take;
            offset += take;
            avail -= take;
        }
        // Best-effort scrubbing of temporaries.
        ks.fill(0);
        core::hint::black_box(&ks);
    }

    /// Returns a uniformly random `u64`.
    pub fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    /// Returns a uniformly random value in `[0, bound)` without modulo bias.
    pub fn below(&mut self, bound: u64) -> u64 {
        assert!(bound != 0);
        let zone = u64::MAX - (u64::MAX % bound);
        loop {
            let v = self.next_u64();
            if v < zone {
                return v % bound;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    #[test]
    fn rfc8439_a1_zero_key() {
        // RFC 8439, Appendix A.1, test vector #1.
        let ks = block(&[0; 32], 0, &[0; 12]);
        let expected = hex::decode::<64>(
            "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7\
             da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
        )
        .unwrap();
        assert_eq!(ks, expected);
    }

    #[test]
    fn rfc8439_2_3_2_block() {
        // RFC 8439, Section 2.3.2.
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        let nonce = [0, 0, 0, 0x09, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let ks = block(&key, 1, &nonce);
        let expected = hex::decode::<64>(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e\
             d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
        )
        .unwrap();
        assert_eq!(ks, expected);
    }

    #[test]
    fn rng_forward_secrecy_and_variety() {
        let mut a = ChaChaRng::from_seed([7; 32]);
        let mut b = ChaChaRng::from_seed([7; 32]);
        assert_eq!(a.next_u64(), b.next_u64(), "deterministic for equal seeds");
        let key_before = a.key;
        let x = a.next_u64();
        assert_ne!(a.key, key_before, "key is erased after every request");
        assert_ne!(x, a.next_u64());
        let mut big = [0u8; 300];
        a.fill_bytes(&mut big);
        assert!(big.iter().any(|&v| v != 0));
        b.reseed(b"extra");
        assert_ne!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn below_is_in_range() {
        let mut r = ChaChaRng::from_seed([1; 32]);
        for bound in [1u64, 2, 3, 10, 1 << 40, u64::MAX] {
            for _ in 0..50 {
                assert!(r.below(bound) < bound);
            }
        }
    }
}
