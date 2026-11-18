//! Local APIC (timer for preemptive scheduling).
//!
//! Supports both xAPIC (MMIO, mapped uncached by `mm::kspace`) and x2APIC (MSR)
//! modes; the mode chosen by the firmware is kept.

use core::sync::atomic::{AtomicU64, Ordering};

use super::entry::{SPURIOUS_VECTOR, TIMER_VECTOR};
use super::msr;
use super::port::outb;

const REG_TPR: u64 = 0x80;
const REG_EOI: u64 = 0xb0;
const REG_SVR: u64 = 0xf0;
const REG_LVT_TIMER: u64 = 0x320;
const REG_TIMER_INIT: u64 = 0x380;
const REG_TIMER_DIV: u64 = 0x3e0;

const X2APIC_ENABLE: u64 = 1 << 10;
const APIC_GLOBAL_ENABLE: u64 = 1 << 11;

/// MMIO base (virtual) in xAPIC mode, 0 in x2APIC mode.
static MMIO: AtomicU64 = AtomicU64::new(0);

/// Physical address of the xAPIC register page.
#[must_use]
pub fn physical_base() -> u64 {
    // SAFETY: IA32_APIC_BASE exists on every x86-64 CPU.
    unsafe { msr::read(msr::IA32_APIC_BASE) & 0x000f_ffff_ffff_f000 }
}

fn x2apic_mode() -> bool {
    // SAFETY: as above.
    unsafe { msr::read(msr::IA32_APIC_BASE) & X2APIC_ENABLE != 0 }
}

fn write(reg: u64, value: u32) {
    let mmio = MMIO.load(Ordering::Relaxed);
    if mmio == 0 {
        // SAFETY: in x2APIC mode every register is an MSR at 0x800 + reg / 16.
        unsafe { msr::write(0x800 + (reg >> 4) as u32, u64::from(value)) };
    } else {
        // SAFETY: `mmio` maps the APIC register page (uncached) for the lifetime
        // of the kernel; `reg` is a valid register offset.
        unsafe { core::ptr::write_volatile((mmio + reg) as *mut u32, value) };
    }
}

/// Masks the legacy 8259 PICs after remapping them away from exception vectors.
fn disable_legacy_pic() {
    // SAFETY: standard 8259 initialisation sequence; afterwards every line is masked.
    unsafe {
        outb(0x20, 0x11);
        outb(0xa0, 0x11);
        outb(0x21, 0xf0); // master vector base 0xf0
        outb(0xa1, 0xf8); // slave vector base 0xf8
        outb(0x21, 0x04);
        outb(0xa1, 0x02);
        outb(0x21, 0x01);
        outb(0xa1, 0x01);
        outb(0x21, 0xff);
        outb(0xa1, 0xff);
    }
}

/// Initialises the local APIC. `mmio_virt` is the kernel mapping of
/// [`physical_base`] (ignored in x2APIC mode).
pub fn init(mmio_virt: u64) {
    disable_legacy_pic();
    // SAFETY: IA32_APIC_BASE exists; we only set the global enable bit.
    unsafe {
        let base = msr::read(msr::IA32_APIC_BASE);
        msr::write(msr::IA32_APIC_BASE, base | APIC_GLOBAL_ENABLE);
    }
    if !x2apic_mode() {
        MMIO.store(mmio_virt, Ordering::Relaxed);
    }
    write(REG_TPR, 0);
    write(REG_SVR, 0x100 | SPURIOUS_VECTOR as u32);
}

/// Starts the periodic scheduler tick.
pub fn start_timer(initial_count: u32) {
    write(REG_TIMER_DIV, 0x3); // divide by 16
    write(REG_LVT_TIMER, TIMER_VECTOR as u32 | (1 << 17)); // periodic
    write(REG_TIMER_INIT, initial_count);
}

/// Signals end of interrupt.
pub fn eoi() {
    write(REG_EOI, 0);
}

/// `true` if the APIC runs in x2APIC mode.
#[must_use]
pub fn is_x2apic() -> bool {
    x2apic_mode()
}
