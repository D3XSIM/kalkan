//! Port-mapped I/O.

use core::arch::asm;

/// Writes a byte to an I/O port.
///
/// # Safety
///
/// Writing to arbitrary ports can reconfigure hardware; the caller must know the
/// device behind `port`.
pub unsafe fn outb(port: u16, value: u8) {
    // SAFETY: guaranteed by the caller.
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags))
    };
}

/// Reads a byte from an I/O port.
///
/// # Safety
///
/// Reading some ports has side effects; the caller must know the device.
pub unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: guaranteed by the caller.
    unsafe {
        asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack, preserves_flags))
    };
    value
}

/// Writes a 32-bit value to an I/O port.
///
/// # Safety
///
/// See [`outb`].
#[allow(dead_code)]
pub unsafe fn outl(port: u16, value: u32) {
    // SAFETY: guaranteed by the caller.
    unsafe {
        asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack, preserves_flags))
    };
}
