//! Hardware entropy sources.

use core::arch::asm;

use super::cpu::Features;
use super::rdtsc;

fn rdseed() -> Option<u64> {
    for _ in 0..64 {
        let (value, ok): (u64, u8);
        // SAFETY: only called when CPUID advertises RDSEED.
        unsafe {
            asm!("rdseed {v}", "setc {ok}", v = out(reg) value, ok = out(reg_byte) ok, options(nomem, nostack));
        }
        if ok == 1 {
            return Some(value);
        }
        core::hint::spin_loop();
    }
    None
}

fn rdrand() -> Option<u64> {
    for _ in 0..16 {
        let (value, ok): (u64, u8);
        // SAFETY: only called when CPUID advertises RDRAND.
        unsafe {
            asm!("rdrand {v}", "setc {ok}", v = out(reg) value, ok = out(reg_byte) ok, options(nomem, nostack));
        }
        if ok == 1 {
            return Some(value);
        }
    }
    None
}

/// Which sources contributed to the seed.
#[derive(Clone, Copy, Debug, Default)]
pub struct Sources {
    pub rdseed: u32,
    pub rdrand: u32,
    pub jitter_samples: u32,
}

/// Gathers a 256-bit seed from every available source, condensed with BLAKE2b.
///
/// Hardware generators are never trusted alone: their output is always mixed with
/// timing jitter, so a backdoored or broken `RDRAND` cannot fully determine the
/// seed by itself.
pub fn seed(f: &Features) -> ([u8; 32], Sources) {
    let mut h = kcore::blake2b::Blake2b::new();
    let mut src = Sources::default();
    h.update(b"kalkan-entropy-v1");
    for _ in 0..8 {
        if f.rdseed
            && let Some(v) = rdseed()
        {
            h.update(&v.to_le_bytes());
            src.rdseed += 1;
        }
        if f.rdrand
            && let Some(v) = rdrand()
        {
            h.update(&v.to_le_bytes());
            src.rdrand += 1;
        }
    }
    // Timing jitter: the low bits of the TSC around a small busy loop.
    let mut prev = rdtsc();
    for i in 0..256u64 {
        let mut x = i;
        for _ in 0..(prev & 0x3f) {
            x = core::hint::black_box(x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1));
        }
        let now = rdtsc();
        h.update(&(now.wrapping_sub(prev) ^ x).to_le_bytes());
        prev = now;
        src.jitter_samples += 1;
    }
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    (out, src)
}
