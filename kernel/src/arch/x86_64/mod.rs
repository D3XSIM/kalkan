//! x86-64 support code.

pub mod apic;
pub mod cpu;
pub mod entry;
pub mod gdt;
pub mod idt;
pub mod msr;
pub mod port;
pub mod rng;
pub mod serial;
pub mod syscall;

use core::arch::asm;
use core::cell::UnsafeCell;

/// Interior-mutable static for CPU structures (GDT, TSS, IDT, per-CPU data).
///
/// Kalkan runs on a single CPU and the kernel never takes interrupts while in
/// kernel mode, so these structures are only ever touched from one context at a
/// time. All accesses go through raw pointers inside `arch`.
#[repr(transparent)]
pub(crate) struct Racy<T>(UnsafeCell<T>);

// SAFETY: see the type documentation — single CPU, no concurrent access.
unsafe impl<T> Sync for Racy<T> {}

impl<T> Racy<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self(UnsafeCell::new(value))
    }

    pub(crate) const fn get(&self) -> *mut T {
        self.0.get()
    }
}

/// Disables interrupts and halts the CPU forever.
pub fn halt_forever() -> ! {
    loop {
        // SAFETY: `cli; hlt` has no memory effects; halting is always sound.
        unsafe { asm!("cli", "hlt", options(nomem, nostack)) };
    }
}

/// Returns `true` if maskable interrupts are enabled.
#[must_use]
pub fn interrupts_enabled() -> bool {
    let flags: u64;
    // SAFETY: reading RFLAGS has no side effects.
    unsafe { asm!("pushfq", "pop {}", out(reg) flags, options(nomem, preserves_flags)) };
    flags & (1 << 9) != 0
}

/// Disables maskable interrupts.
pub fn disable_interrupts() {
    // SAFETY: `cli` only affects the interrupt flag.
    unsafe { asm!("cli", options(nomem, nostack)) };
}

/// Enables maskable interrupts.
pub fn enable_interrupts() {
    // SAFETY: `sti` only affects the interrupt flag. The kernel never enables
    // interrupts while it is in an inconsistent state (see `sync::SpinLock`).
    unsafe { asm!("sti", options(nomem, nostack)) };
}

/// Faulting address of the most recent page fault.
#[must_use]
pub fn read_cr2() -> u64 {
    let v: u64;
    // SAFETY: reading CR2 has no side effects.
    unsafe { asm!("mov {}, cr2", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// Physical address of the active top-level page table.
#[must_use]
pub fn read_cr3() -> u64 {
    let v: u64;
    // SAFETY: reading CR3 has no side effects.
    unsafe { asm!("mov {}, cr3", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v & 0x000f_ffff_ffff_f000
}

/// Loads a new top-level page table.
///
/// # Safety
///
/// `pml4` must be the physical address of a valid PML4 that maps the currently
/// executing code, the current stack and all kernel data.
pub unsafe fn write_cr3(pml4: u64) {
    // SAFETY: guaranteed by the caller.
    unsafe { asm!("mov cr3, {}", in(reg) pml4, options(nostack, preserves_flags)) };
}

/// Invalidates the TLB entry for one page in the current address space.
pub fn invlpg(addr: u64) {
    // SAFETY: invalidating a TLB entry can only cause a re-walk of the page tables.
    unsafe { asm!("invlpg [{}]", in(reg) addr, options(nostack, preserves_flags)) };
}

/// Reads the time stamp counter.
#[must_use]
pub fn rdtsc() -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: rdtsc is always available in ring 0 (CR4.TSD only restricts ring 3).
    unsafe {
        asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags))
    };
    (u64::from(hi) << 32) | u64::from(lo)
}

/// Shuts the machine down.
///
/// With the `qemu-exit` feature the QEMU `isa-debug-exit` device is used so that a
/// test run can report success or failure to the host; otherwise the CPU halts.
pub fn shutdown(success: bool) -> ! {
    #[cfg(feature = "qemu-exit")]
    {
        // QEMU exits with status (value << 1) | 1: 0x10 -> 33 (pass), 0x11 -> 35 (fail).
        let value: u32 = if success { 0x10 } else { 0x11 };
        // SAFETY: port 0xf4 is the isa-debug-exit device configured by `cargo xtask`.
        unsafe { port::outl(0xf4, value) };
    }
    let _ = success;
    halt_forever()
}
