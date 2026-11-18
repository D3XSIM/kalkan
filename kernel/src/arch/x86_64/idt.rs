//! Interrupt descriptor table.
//!
//! All 256 vectors use interrupt gates with **DPL 0**: user code can never invoke
//! any vector with the `int` instruction (it gets a #GP instead). Double fault,
//! NMI and machine check run on dedicated, guard-paged IST stacks so that even a
//! kernel stack overflow is reported instead of silently triple-faulting.

use core::arch::asm;
use core::mem::size_of;

use super::Racy;
use super::gdt;

#[derive(Clone, Copy)]
#[repr(C)]
struct Gate {
    offset_low: u16,
    selector: u16,
    ist: u8,
    attributes: u8,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

const EMPTY: Gate = Gate {
    offset_low: 0,
    selector: 0,
    ist: 0,
    attributes: 0,
    offset_mid: 0,
    offset_high: 0,
    reserved: 0,
};

#[repr(C, align(16))]
struct Idt([Gate; 256]);

static IDT: Racy<Idt> = Racy::new(Idt([EMPTY; 256]));

#[repr(C, packed)]
struct Pointer {
    limit: u16,
    base: u64,
}

unsafe extern "C" {
    /// 256 entry stubs, 16 bytes apart (see `entry.rs`).
    static kalkan_isr_stubs: u8;
}

/// Builds and loads the IDT.
pub fn init() {
    let stubs = &raw const kalkan_isr_stubs as u64;
    // SAFETY: single CPU during early boot; nothing else touches the IDT.
    let idt = unsafe { &mut *IDT.get() };
    for (vector, gate) in idt.0.iter_mut().enumerate() {
        let handler = stubs + vector as u64 * 16;
        let ist = match vector {
            2 => gdt::IST_NMI,
            8 => gdt::IST_DOUBLE_FAULT,
            18 => gdt::IST_MACHINE_CHECK,
            _ => 0,
        };
        *gate = Gate {
            offset_low: handler as u16,
            selector: gdt::KERNEL_CS,
            ist,
            attributes: 0x8e, // present, DPL 0, 64-bit interrupt gate
            offset_mid: (handler >> 16) as u16,
            offset_high: (handler >> 32) as u32,
            reserved: 0,
        };
    }
    let ptr = Pointer {
        limit: (size_of::<Idt>() - 1) as u16,
        base: IDT.get() as u64,
    };
    // SAFETY: the IDT is fully initialised and lives forever.
    unsafe { asm!("lidt [{}]", in(reg) &ptr, options(readonly, nostack, preserves_flags)) };
}
