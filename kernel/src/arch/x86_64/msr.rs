//! Model specific registers.

use core::arch::asm;

pub const IA32_APIC_BASE: u32 = 0x1b;
pub const IA32_SPEC_CTRL: u32 = 0x48;
pub const IA32_PRED_CMD: u32 = 0x49;
pub const IA32_SYSENTER_CS: u32 = 0x174;
pub const IA32_SYSENTER_ESP: u32 = 0x175;
pub const IA32_SYSENTER_EIP: u32 = 0x176;
pub const IA32_EFER: u32 = 0xc000_0080;
pub const IA32_STAR: u32 = 0xc000_0081;
pub const IA32_LSTAR: u32 = 0xc000_0082;
pub const IA32_CSTAR: u32 = 0xc000_0083;
pub const IA32_FMASK: u32 = 0xc000_0084;
pub const IA32_FS_BASE: u32 = 0xc000_0100;
pub const IA32_GS_BASE: u32 = 0xc000_0101;
pub const IA32_KERNEL_GS_BASE: u32 = 0xc000_0102;

/// Reads an MSR.
///
/// # Safety
///
/// The MSR must exist on this CPU (otherwise `#GP`).
pub unsafe fn read(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: guaranteed by the caller.
    unsafe {
        asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags))
    };
    (u64::from(hi) << 32) | u64::from(lo)
}

/// Writes an MSR.
///
/// # Safety
///
/// The MSR must exist and the value must not break kernel invariants.
pub unsafe fn write(msr: u32, value: u64) {
    let (lo, hi) = (value as u32, (value >> 32) as u32);
    // SAFETY: guaranteed by the caller.
    unsafe {
        asm!("wrmsr", in("ecx") msr, in("eax") lo, in("edx") hi, options(nostack, preserves_flags))
    };
}
