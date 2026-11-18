//! `syscall` instruction setup and per-CPU data.

use super::Racy;
use super::entry::syscall_entry_address;
use super::gdt::{KERNEL_CS, KERNEL_DS};
use super::msr;

/// Per-CPU data reached through `GS` in the system call entry stub.
/// Field offsets are hard-coded in `entry.rs`.
#[repr(C)]
struct PerCpu {
    /// Offset 0: top of the kernel stack.
    kernel_rsp: u64,
    /// Offset 8: scratch slot for the user stack pointer.
    user_rsp: u64,
}

static PERCPU: Racy<PerCpu> = Racy::new(PerCpu {
    kernel_rsp: 0,
    user_rsp: 0,
});

/// RFLAGS bits cleared on `syscall`: TF, IF, DF, IOPL, NT, AC.
const FMASK: u64 = (1 << 8) | (1 << 9) | (1 << 10) | (3 << 12) | (1 << 14) | (1 << 18);

/// Programs the `syscall` MSRs. `kernel_stack_top` is used for every entry.
pub fn init(kernel_stack_top: u64) {
    // SAFETY: single CPU; the per-CPU block is only read by the entry stub.
    unsafe { (*PERCPU.get()).kernel_rsp = kernel_stack_top };
    // The user-mode selectors are derived by the CPU from STAR[63:48]:
    // CS = base + 16 (0x20 | 3), SS = base + 8 (0x18 | 3).
    let star = (u64::from(KERNEL_DS) << 48) | (u64::from(KERNEL_CS) << 32);
    // SAFETY: these MSRs exist on every x86-64 CPU (EFER.SCE was enabled by
    // `cpu::harden`). GS_BASE points at the per-CPU block while in the kernel and
    // KERNEL_GS_BASE holds the (zero) user value until the first `swapgs`.
    unsafe {
        msr::write(msr::IA32_STAR, star);
        msr::write(msr::IA32_LSTAR, syscall_entry_address());
        msr::write(msr::IA32_CSTAR, 0);
        msr::write(msr::IA32_FMASK, FMASK);
        msr::write(msr::IA32_FS_BASE, 0);
        msr::write(msr::IA32_GS_BASE, PERCPU.get() as u64);
        msr::write(msr::IA32_KERNEL_GS_BASE, 0);
    }
}
