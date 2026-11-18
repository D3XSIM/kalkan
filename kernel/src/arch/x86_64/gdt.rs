//! Global descriptor table and task state segment.
//!
//! The layout is dictated by `syscall`/`sysret` (see `syscall.rs`):
//!
//! | Selector | Descriptor             |
//! |----------|------------------------|
//! | `0x08`   | kernel code (64-bit)   |
//! | `0x10`   | kernel data            |
//! | `0x18`   | user data   (DPL 3)    |
//! | `0x20`   | user code   (DPL 3)    |
//! | `0x28`   | TSS (16 bytes)         |
//!
//! The TSS has **no I/O permission bitmap** (`iomap_base` beyond the limit), so user
//! code can never access I/O ports.

use core::arch::asm;
use core::mem::size_of;

use super::Racy;

pub const KERNEL_CS: u16 = 0x08;
pub const KERNEL_DS: u16 = 0x10;
pub const USER_DS: u16 = 0x18 | 3;
pub const USER_CS: u16 = 0x20 | 3;
const TSS_SEL: u16 = 0x28;

#[repr(C, packed(4))]
struct Tss {
    reserved0: u32,
    rsp: [u64; 3],
    reserved1: u64,
    ist: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    iomap_base: u16,
}

#[repr(C, align(16))]
struct Gdt([u64; 7]);

#[repr(C, packed)]
struct Pointer {
    limit: u16,
    base: u64,
}

static TSS: Racy<Tss> = Racy::new(Tss {
    reserved0: 0,
    rsp: [0; 3],
    reserved1: 0,
    ist: [0; 7],
    reserved2: 0,
    reserved3: 0,
    iomap_base: size_of::<Tss>() as u16,
});

static GDT: Racy<Gdt> = Racy::new(Gdt([
    0,
    0x00af_9b00_0000_ffff, // kernel code: present, DPL0, 64-bit, accessed
    0x00cf_9300_0000_ffff, // kernel data: present, DPL0, writable, accessed
    0x00cf_f300_0000_ffff, // user data:   present, DPL3, writable, accessed
    0x00af_fb00_0000_ffff, // user code:   present, DPL3, 64-bit, accessed
    0,                     // TSS low  (filled in at runtime)
    0,                     // TSS high
]));

/// Early IST stacks used until the guarded stacks are mapped.
#[repr(C, align(16))]
struct EarlyStacks([[u8; 8192]; IST_COUNT]);
static EARLY_IST: Racy<EarlyStacks> = Racy::new(EarlyStacks([[0; 8192]; IST_COUNT]));

/// IST index (1-based, as stored in IDT entries) for each critical exception.
pub const IST_DOUBLE_FAULT: u8 = 1;
pub const IST_NMI: u8 = 2;
pub const IST_MACHINE_CHECK: u8 = 3;
/// `#DB` gets its own stack too: it is the one exception that could, in principle,
/// be delivered at the very first instruction of the system call entry point,
/// where `rsp` still holds a user-controlled value (cf. CVE-2018-8897).
pub const IST_DEBUG: u8 = 4;
/// Number of interrupt stacks.
pub const IST_COUNT: usize = 4;

/// Loads the GDT and TSS and reloads every segment register.
pub fn init() {
    let tss_base = TSS.get() as u64;
    let limit = (size_of::<Tss>() - 1) as u64;
    let low = (limit & 0xffff)
        | ((tss_base & 0x00ff_ffff) << 16)
        | (0x89 << 40) // present, DPL0, available 64-bit TSS
        | (((limit >> 16) & 0xf) << 48)
        | (((tss_base >> 24) & 0xff) << 56);
    let high = tss_base >> 32;

    let early = EARLY_IST.get() as u64;
    // SAFETY: single CPU during early boot; no other code accesses GDT/TSS yet.
    unsafe {
        let gdt = &mut *GDT.get();
        gdt.0[5] = low;
        gdt.0[6] = high;
        let tss = &mut *TSS.get();
        let mut ist = tss.ist;
        for (i, slot) in ist.iter_mut().take(IST_COUNT).enumerate() {
            *slot = early + (i as u64 + 1) * 8192;
        }
        tss.ist = ist;
    }

    let ptr = Pointer {
        limit: (size_of::<Gdt>() - 1) as u16,
        base: GDT.get() as u64,
    };
    // SAFETY: the GDT is valid and lives forever. Reloading CS through a far return
    // and the data segments with valid selectors keeps execution on the same
    // flat address space. FS/GS are loaded with the null selector *before* their
    // base MSRs are programmed (see `syscall::init`).
    unsafe {
        asm!(
            "lgdt [{ptr}]",
            "push {cs}",
            "lea {tmp}, [rip + 2f]",
            "push {tmp}",
            "retfq",
            "2:",
            "mov ds, {ds:x}",
            "mov es, {ds:x}",
            "mov ss, {ds:x}",
            "xor {tmp:e}, {tmp:e}",
            "mov fs, {tmp:x}",
            "mov gs, {tmp:x}",
            // No local descriptor table: user code can never install descriptors
            // (call gates, 32-bit code segments) of its own.
            "lldt {tmp:x}",
            "ltr {tss:x}",
            ptr = in(reg) &ptr,
            cs = in(reg) u64::from(KERNEL_CS),
            ds = in(reg) u64::from(KERNEL_DS),
            tss = in(reg) u64::from(TSS_SEL),
            tmp = out(reg) _,
        );
    }
}

/// Sets the stack used when an interrupt arrives from user mode.
pub fn set_kernel_stack(top: u64) {
    // SAFETY: single CPU; the TSS is only read by hardware on privilege changes,
    // which cannot happen while the kernel is running.
    unsafe { (*TSS.get()).rsp[0] = top };
}

/// Installs the guarded interrupt stacks (`tops[i]` for IST `i + 1`).
pub fn set_interrupt_stacks(tops: [u64; IST_COUNT]) {
    // SAFETY: as above.
    unsafe {
        let tss = &mut *TSS.get();
        let mut ist = tss.ist;
        ist[..IST_COUNT].copy_from_slice(&tops);
        tss.ist = ist;
    }
}
