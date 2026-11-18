//! CPU feature detection and hardware hardening.
//!
//! The kernel refuses to boot (fail-closed) on CPUs that lack the protections its
//! security model depends on: NX, SMEP and SMAP.

use core::arch::asm;
use core::sync::atomic::{AtomicBool, Ordering};

use super::msr;

/// Executes `cpuid`.
#[must_use]
pub fn cpuid(leaf: u32, sub: u32) -> [u32; 4] {
    let (a, b, c, d): (u32, u64, u32, u32);
    // SAFETY: cpuid is available on every x86-64 CPU. rbx is reserved by LLVM, so
    // it is saved and restored around the instruction.
    unsafe {
        asm!(
            "mov {t}, rbx",
            "cpuid",
            "xchg {t}, rbx",
            t = out(reg) b,
            inout("eax") leaf => a,
            inout("ecx") sub => c,
            out("edx") d,
            options(nomem, nostack, preserves_flags),
        );
    }
    [a, b as u32, c, d]
}

/// Detected CPU features relevant to the kernel.
#[derive(Clone, Copy, Debug, Default)]
pub struct Features {
    pub vendor: [u8; 12],
    pub nx: bool,
    pub smep: bool,
    pub smap: bool,
    pub umip: bool,
    pub rdrand: bool,
    pub rdseed: bool,
    pub fsgsbase: bool,
    pub x2apic: bool,
    pub ibpb: bool,
    pub stibp: bool,
    pub md_clear: bool,
    pub cet_ss: bool,
    pub la57: bool,
}

/// Queries the CPU.
#[must_use]
pub fn detect() -> Features {
    let mut f = Features::default();
    let l0 = cpuid(0, 0);
    let max_leaf = l0[0];
    f.vendor[..4].copy_from_slice(&l0[1].to_le_bytes());
    f.vendor[4..8].copy_from_slice(&l0[3].to_le_bytes());
    f.vendor[8..].copy_from_slice(&l0[2].to_le_bytes());

    let l1 = cpuid(1, 0);
    f.rdrand = l1[2] & (1 << 30) != 0;
    f.x2apic = l1[2] & (1 << 21) != 0;

    if max_leaf >= 7 {
        let l7 = cpuid(7, 0);
        f.fsgsbase = l7[1] & (1 << 0) != 0;
        f.smep = l7[1] & (1 << 7) != 0;
        f.rdseed = l7[1] & (1 << 18) != 0;
        f.smap = l7[1] & (1 << 20) != 0;
        f.umip = l7[2] & (1 << 2) != 0;
        f.cet_ss = l7[2] & (1 << 7) != 0;
        f.la57 = l7[2] & (1 << 16) != 0;
        f.md_clear = l7[3] & (1 << 10) != 0;
        f.ibpb = l7[3] & (1 << 26) != 0;
        f.stibp = l7[3] & (1 << 27) != 0;
    }

    let max_ext = cpuid(0x8000_0000, 0)[0];
    if max_ext >= 0x8000_0001 {
        f.nx = cpuid(0x8000_0001, 0)[3] & (1 << 20) != 0;
    }
    f
}

mod cr0 {
    pub const EM: u64 = 1 << 2;
    pub const TS: u64 = 1 << 3;
    pub const WP: u64 = 1 << 16;
    pub const AM: u64 = 1 << 18;
}

mod cr4 {
    pub const TSD: u64 = 1 << 2;
    pub const PCE: u64 = 1 << 8;
    pub const PGE: u64 = 1 << 7;
    pub const OSFXSR: u64 = 1 << 9;
    pub const OSXMMEXCPT: u64 = 1 << 10;
    pub const UMIP: u64 = 1 << 11;
    pub const FSGSBASE: u64 = 1 << 16;
    pub const PCIDE: u64 = 1 << 17;
    pub const OSXSAVE: u64 = 1 << 18;
    pub const SMEP: u64 = 1 << 20;
    pub const SMAP: u64 = 1 << 21;
    pub const CET: u64 = 1 << 23;
}

const EFER_SCE: u64 = 1 << 0;
const EFER_NXE: u64 = 1 << 11;

#[must_use]
pub fn read_cr0() -> u64 {
    let v: u64;
    // SAFETY: reading CR0 has no side effects.
    unsafe { asm!("mov {}, cr0", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

#[must_use]
pub fn read_cr4() -> u64 {
    let v: u64;
    // SAFETY: reading CR4 has no side effects.
    unsafe { asm!("mov {}, cr4", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// The security-relevant control register state actually in effect.
#[derive(Clone, Copy, Debug)]
pub struct Posture {
    pub nx: bool,
    pub smep: bool,
    pub smap: bool,
    pub umip: bool,
    pub wp: bool,
    pub tsd: bool,
    pub simd_disabled: bool,
    pub fsgsbase_disabled: bool,
}

/// Why the CPU is unacceptable.
#[derive(Clone, Copy, Debug)]
pub enum Unsupported {
    Nx,
    Smep,
    Smap,
}

/// Enables every available hardware protection and verifies the result.
///
/// * `EFER.NXE`   — no-execute pages (data is never executable).
/// * `CR0.WP`     — the kernel itself cannot write to read-only pages.
/// * `CR4.SMEP`   — the kernel can never execute user memory.
/// * `CR4.SMAP`   — the kernel can never access user memory by accident.
/// * `CR4.UMIP`   — user mode cannot read GDT/IDT/LDT/TR addresses (KASLR leaks).
/// * `CR4.TSD`    — `rdtsc` is privileged: no high resolution timer for cache
///   timing attacks from user space.
/// * x87/SSE/AVX disabled (`CR0.EM`, `CR4.OSFXSR=0`, `CR4.OSXSAVE=0`): user code
///   cannot use vector registers, so no SIMD state can ever leak between
///   processes (cf. LazyFP, CVE-2018-3665).
/// * `CR4.FSGSBASE=0` — user space cannot change its GS base under the kernel.
pub fn harden(f: &Features) -> Result<Posture, Unsupported> {
    if !f.nx {
        return Err(Unsupported::Nx);
    }
    if !f.smep {
        return Err(Unsupported::Smep);
    }
    if !f.smap {
        return Err(Unsupported::Smap);
    }

    // SAFETY: EFER exists on every x86-64 CPU; NXE and SCE are supported (NX was
    // checked above, SYSCALL is architectural in long mode).
    unsafe {
        let efer = msr::read(msr::IA32_EFER);
        msr::write(msr::IA32_EFER, efer | EFER_NXE | EFER_SCE);
    }

    let mut c0 = read_cr0();
    c0 |= cr0::WP | cr0::EM | cr0::TS;
    c0 &= !cr0::AM;
    // SAFETY: the kernel is built for soft-float and never executes x87/SSE
    // instructions, so trapping them is harmless; WP only adds protection.
    unsafe { asm!("mov cr0, {}", in(reg) c0, options(nostack, preserves_flags)) };

    let mut c4 = read_cr4();
    c4 |= cr4::SMEP | cr4::SMAP | cr4::TSD | cr4::PGE;
    if f.umip {
        c4 |= cr4::UMIP;
    }
    c4 &= !(cr4::OSFXSR
        | cr4::OSXMMEXCPT
        | cr4::OSXSAVE
        | cr4::FSGSBASE
        | cr4::PCE
        | cr4::PCIDE
        | cr4::CET);
    // SAFETY: every bit set here was verified to be supported above. The kernel
    // never accesses user memory through user addresses (see `mm::user`), so SMAP
    // can stay enabled at all times.
    unsafe { asm!("mov cr4, {}", in(reg) c4, options(nostack, preserves_flags)) };

    // Read everything back: report what is *actually* in effect.
    let c0 = read_cr0();
    let c4 = read_cr4();
    // SAFETY: EFER exists.
    let efer = unsafe { msr::read(msr::IA32_EFER) };
    Ok(Posture {
        nx: efer & EFER_NXE != 0,
        smep: c4 & cr4::SMEP != 0,
        smap: c4 & cr4::SMAP != 0,
        umip: c4 & cr4::UMIP != 0,
        wp: c0 & cr0::WP != 0,
        tsd: c4 & cr4::TSD != 0,
        simd_disabled: c0 & cr0::EM != 0 && c4 & (cr4::OSFXSR | cr4::OSXSAVE) == 0,
        fsgsbase_disabled: c4 & cr4::FSGSBASE == 0,
    })
}

static HAS_IBPB: AtomicBool = AtomicBool::new(false);
static HAS_MD_CLEAR: AtomicBool = AtomicBool::new(false);

/// Enables the speculative-execution mitigations the CPU offers.
///
/// IBRS and STIBP are switched on once and left on ("always on" mode, the
/// intended mode on CPUs with enhanced IBRS): user space can then no longer
/// steer the kernel's indirect branch predictions (Spectre v2), nor can sibling
/// hyper-threads influence each other. Returns `(ibrs, stibp)`.
pub fn enable_mitigations(f: &Features) -> (bool, bool) {
    HAS_IBPB.store(f.ibpb, Ordering::Relaxed);
    HAS_MD_CLEAR.store(f.md_clear, Ordering::Relaxed);
    let bits = u64::from(f.ibpb) | (u64::from(f.stibp) << 1);
    if bits != 0 {
        // SAFETY: IA32_SPEC_CTRL exists when CPUID advertises IBRS or STIBP, and
        // only the advertised bits are set.
        unsafe {
            let v = msr::read(msr::IA32_SPEC_CTRL);
            msr::write(msr::IA32_SPEC_CTRL, v | bits);
        }
    }
    (f.ibpb, f.stibp)
}

/// Indirect Branch Prediction Barrier: prevents branch predictor state trained by
/// one address space from steering speculation in another (Spectre v2).
pub fn ibpb() {
    if HAS_IBPB.load(Ordering::Relaxed) {
        // SAFETY: IA32_PRED_CMD exists when CPUID advertises IBRS/IBPB.
        unsafe { msr::write(msr::IA32_PRED_CMD, 1) };
    }
}

/// Clears CPU micro-architectural buffers before returning to user mode (MDS).
pub fn clear_cpu_buffers() {
    if HAS_MD_CLEAR.load(Ordering::Relaxed) {
        let sel: u16 = super::gdt::KERNEL_DS;
        // SAFETY: `verw` with a valid selector has no architectural side effects
        // besides ZF; on MD_CLEAR CPUs it also flushes the affected buffers.
        unsafe { asm!("verw [{}]", in(reg) &sel, options(nostack)) };
    }
}
