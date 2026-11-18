//! Spectre variant 1 (bounds check bypass) hardening.
//!
//! A bounds check such as `if i < len { table[i] }` can be bypassed *speculatively*:
//! the CPU may execute `table[i]` with an out-of-bounds `i` before the comparison
//! retires, leaving a secret-dependent footprint in the cache. Every index that
//! comes from user space (system call numbers, capability slots) is therefore
//! additionally clamped with a branch-free mask after the architectural check, in
//! the spirit of Linux's `array_index_nospec`.
//!
//! [`core::hint::black_box`] keeps the optimiser from proving the mask redundant
//! (it otherwise *knows* `i < len` after the branch and would delete it). This is a
//! best-effort mitigation implemented in safe Rust.

/// Returns an all-ones mask if `index < len`, otherwise zero, without branching.
///
/// `len` must be non-zero and `<= isize::MAX`, which holds for every table in the
/// kernel.
#[inline(always)]
#[must_use]
pub fn index_mask(index: usize, len: usize) -> usize {
    // Same construction as Linux's generic `array_index_mask_nospec`:
    // the top bit of `index | (len - 1 - index)` is set iff index >= len.
    let len_m1 = len.wrapping_sub(1);
    let v = index | len_m1.wrapping_sub(index);
    let mask = !((v as isize) >> (usize::BITS - 1)) as usize;
    core::hint::black_box(mask)
}

/// Bounds-checks `index` against `len` and returns a speculation-safe index.
#[inline(always)]
#[must_use]
pub fn clamp(index: u64, len: usize) -> Option<usize> {
    let index = usize::try_from(index).ok()?;
    if index < len {
        Some(index & index_mask(index, len))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_values() {
        for len in 1..70usize {
            for i in 0..140usize {
                let m = index_mask(i, len);
                if i < len {
                    assert_eq!(m, usize::MAX, "i={i} len={len}");
                } else {
                    assert_eq!(m, 0, "i={i} len={len}");
                }
            }
        }
        assert_eq!(index_mask(usize::MAX, 64), 0);
        assert_eq!(index_mask(usize::MAX / 2 + 3, 64), 0);
    }

    #[test]
    fn clamp_rejects() {
        assert_eq!(clamp(3, 4), Some(3));
        assert_eq!(clamp(4, 4), None);
        assert_eq!(clamp(u64::MAX, 4), None);
    }
}
