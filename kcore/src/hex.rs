//! Tiny hexadecimal helpers and a constant-time comparison.

/// Decodes exactly `N` bytes from a hex string (upper or lower case).
#[must_use]
pub fn decode<const N: usize>(s: &str) -> Option<[u8; N]> {
    let s = s.trim().as_bytes();
    if s.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = nibble(s[2 * i])?;
        let lo = nibble(s[2 * i + 1])?;
        *byte = (hi << 4) | lo;
    }
    Some(out)
}

const fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Lower-case hex digit for a nibble.
#[must_use]
pub const fn digit(n: u8) -> char {
    (if n < 10 { b'0' + n } else { b'a' + n - 10 }) as char
}

/// Compares two byte strings in time independent of their contents.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    core::hint::black_box(diff) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_roundtrip() {
        assert_eq!(decode::<2>("beEF"), Some([0xbe, 0xef]));
        assert_eq!(decode::<2>("beE"), None);
        assert_eq!(decode::<1>("zz"), None);
        assert_eq!(decode::<1>(" 0a\n"), Some([0x0a]));
    }

    #[test]
    fn ct() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}
