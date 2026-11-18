//! BLAKE2b (RFC 7693).
//!
//! Used to verify the integrity of boot modules: the build system computes the
//! BLAKE2b-512 digest of every user-space image, the bootloader (Limine) checks it
//! before loading, and the kernel checks it *again* against digests compiled into
//! the kernel image before it creates any process.

const IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/// Length of a BLAKE2b-512 digest in bytes.
pub const DIGEST_LEN: usize = 64;

/// Incremental BLAKE2b-512 hasher (unkeyed).
#[derive(Clone, Debug)]
pub struct Blake2b {
    h: [u64; 8],
    t: u128,
    buf: [u8; 128],
    buf_len: usize,
}

impl Default for Blake2b {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake2b {
    /// New hasher with a 64-byte output.
    #[must_use]
    pub const fn new() -> Self {
        let mut h = IV;
        // Parameter block: digest length 64, key length 0, fanout 1, depth 1.
        h[0] ^= 0x0101_0000 ^ (DIGEST_LEN as u64);
        Self {
            h,
            t: 0,
            buf: [0; 128],
            buf_len: 0,
        }
    }

    #[inline(always)]
    fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
        v[d] = (v[d] ^ v[a]).rotate_right(32);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(24);
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
        v[d] = (v[d] ^ v[a]).rotate_right(16);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(63);
    }

    fn compress(&mut self, block: &[u8; 128], last: bool) {
        let mut m = [0u64; 16];
        for (i, word) in m.iter_mut().enumerate() {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&block[i * 8..i * 8 + 8]);
            *word = u64::from_le_bytes(bytes);
        }
        let mut v = [0u64; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..].copy_from_slice(&IV);
        v[12] ^= self.t as u64;
        v[13] ^= (self.t >> 64) as u64;
        if last {
            v[14] = !v[14];
        }
        for s in &SIGMA {
            Self::g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            Self::g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            Self::g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            Self::g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            Self::g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            Self::g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            Self::g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            Self::g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }

    /// Absorbs data.
    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            // Only compress a full buffer once more data is known to follow, because
            // the final block must be compressed with the `last` flag.
            if self.buf_len == 128 {
                self.t = self.t.wrapping_add(128);
                let block = self.buf;
                self.compress(&block, false);
                self.buf_len = 0;
            }
            let take = (128 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
        }
    }

    /// Finishes the computation and returns the 64-byte digest.
    #[must_use]
    pub fn finalize(mut self) -> [u8; DIGEST_LEN] {
        self.t = self.t.wrapping_add(self.buf_len as u128);
        self.buf[self.buf_len..].fill(0);
        let block = self.buf;
        self.compress(&block, true);
        let mut out = [0u8; DIGEST_LEN];
        for (i, word) in self.h.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
        }
        out
    }
}

/// One-shot BLAKE2b-512.
#[must_use]
pub fn hash(data: &[u8]) -> [u8; DIGEST_LEN] {
    let mut h = Blake2b::new();
    h.update(data);
    h.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    fn hex64(s: &str) -> [u8; 64] {
        hex::decode::<64>(s).unwrap()
    }

    #[test]
    fn rfc7693_abc() {
        // RFC 7693, Appendix A.
        assert_eq!(
            hash(b"abc"),
            hex64(
                "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
                 7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
            )
        );
    }

    #[test]
    fn empty() {
        assert_eq!(
            hash(b""),
            hex64(
                "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419\
                 d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
            )
        );
    }

    #[test]
    fn incremental_matches_one_shot() {
        let data: std::vec::Vec<u8> = (0..1000u32).map(|i| (i * 7 + 3) as u8).collect();
        let reference = hash(&data);
        for split in [0usize, 1, 127, 128, 129, 255, 256, 257, 999, 1000] {
            let mut h = Blake2b::new();
            h.update(&data[..split]);
            h.update(&data[split..]);
            assert_eq!(h.finalize(), reference, "split at {split}");
        }
        // Exactly one block must not be compressed twice.
        let block = [0x61u8; 128];
        let mut h = Blake2b::new();
        for b in block.chunks(16) {
            h.update(b);
        }
        assert_eq!(h.finalize(), hash(&block));
    }

    /// Deterministic test data (the Python script that produced the reference
    /// digests uses the same formula).
    fn pattern(n: usize) -> std::vec::Vec<u8> {
        (0..n)
            .map(|i| (((i * 167 + 13) ^ (i >> 8)) & 0xff) as u8)
            .collect()
    }

    /// Digests computed with an independent implementation (Python's `hashlib`,
    /// i.e. OpenSSL/libb2) for inputs around every block boundary.
    #[test]
    fn cross_checked_against_hashlib() {
        let vectors: [(usize, &str); 12] = [
            (
                1,
                "f5e25392a404fdde29fff6087777f9087d7c216ad4213030b011c1aabc9c7592ef7b3b8ff318c272a31fe7a827400db89e4932c3cf0808d0cb9388b560336cfe",
            ),
            (
                63,
                "fb43ee818e1e43bec5764a788a1e0213f2953e6c40bb2eb20cb50ae717d7b83e15f720558c96296678f64f0de2cdf3d28b26f583e7f7c743cd09d07624b8ece5",
            ),
            (
                64,
                "6e385958481a300261de8fbfe92432278220fd9ed8ed2142b7a86387d3360adba2ef933657a52670bc8e2947d048644db0e18ad1c4a8546fcdceefb2295e1432",
            ),
            (
                127,
                "2a2bf0c7eb6c5f7bbb923a1236894af3bb435ffe0d43d14e310055ef0c3848ba4ef64e625c08d6e84dcee4ee1b89a73d306c23e809abc76d075956f325b5519d",
            ),
            (
                128,
                "cfd60fd01809f22c0c1ae01f4f73227373273470eba2bd875e66c9127ade1c2f91aa3164aa5a0fd492bb7813e1a8c705ab3b5bf6a317ce7ce4d4308f693753b2",
            ),
            (
                129,
                "05a880ec1f4512c1136fe0cda87c6e2c2af4958b28979c932a3596190f4cb1a12be2c11f5d1d8f17e69c702e22fb7fb2dbeb071060c9566108809152ea14b5c3",
            ),
            (
                255,
                "15ed289a32e07e43cf74a221cd1170309e8c08de518877675a67d7dd0e0adbecc1e0bfd6ca45fe311d9c8ed1f6b72d8bd2ee258a64dfa73aaa11bcd12c666eab",
            ),
            (
                256,
                "f552db3d0ed73999d4b8e70dd3e210fd39843889e9d961902b39965aa6da84443c421ee0ed9c996262eeefcd588f5f7981648eca9ac61617d11a80c6b73ebfef",
            ),
            (
                257,
                "ea036ecee40e61bf2365fc2cfa92cb9db53eb4c004cd69bd74279e5ce66840e858c56d9a9e164a387e14582cb7baecd23043bc184750ccbc880d32d860666f5a",
            ),
            (
                1000,
                "a20557f0857acb32f39b1ebf0f37a8446523790a6f2a324aefebcadd5a04773c38b97e458148a8efed912b868b57b6471c3feef1cdd694462ec3e3e1d084480d",
            ),
            (
                4096,
                "87896c9d8c1878f1a4e9cfe8c3d5089edf4357240f806f7b2f2364b6130fac4d7a7c9378cca4a36ba7b848d17b2af84595d21ecf4f7c5b4c4b8a102ca7bee5cf",
            ),
            (
                65537,
                "930164f703a81371af104d9744b843d5a42749c8aeee0c0569431f5677b9ac14bba8819cf4fac4b1fdbffd8f2a1596e75c3227ea9719897dc0e94d2f16c35582",
            ),
        ];
        for (len, expected) in vectors {
            let data = pattern(len);
            assert_eq!(hash(&data), hex64(expected), "one-shot, {len} bytes");
            // The same input fed in uneven pieces must give the same digest.
            for chunk in [1usize, 7, 127, 128, 129, 1000] {
                let mut h = Blake2b::new();
                for piece in data.chunks(chunk) {
                    h.update(piece);
                }
                assert_eq!(
                    h.finalize(),
                    hex64(expected),
                    "{len} bytes in chunks of {chunk}"
                );
            }
        }
    }

    #[test]
    fn single_bit_changes_the_digest() {
        let base = pattern(300);
        let reference = hash(&base);
        for bit in 0..300 * 8 {
            let mut data = base.clone();
            data[bit / 8] ^= 1 << (bit % 8);
            assert_ne!(hash(&data), reference, "bit {bit}");
        }
    }
}
