//! 16550 UART on COM1, used for the kernel log.

use super::port::{inb, outb};

const COM1: u16 = 0x3f8;

/// Initialises COM1 at 115200 baud, 8N1, interrupts disabled.
pub fn init() {
    // SAFETY: COM1 is the standard PC serial port; these writes only configure it.
    unsafe {
        outb(COM1 + 1, 0x00); // disable UART interrupts
        outb(COM1 + 3, 0x80); // enable divisor latch
        outb(COM1, 0x01); // divisor 1 -> 115200 baud
        outb(COM1 + 1, 0x00);
        outb(COM1 + 3, 0x03); // 8 bits, no parity, one stop bit
        outb(COM1 + 2, 0xc7); // enable and clear FIFOs
        outb(COM1 + 4, 0x03); // DTR + RTS, OUT2 off (no IRQs)
    }
}

fn put(byte: u8) {
    // Bounded wait so a missing UART can never hang the kernel.
    for _ in 0..100_000 {
        // SAFETY: reading the line status register has no side effects.
        if unsafe { inb(COM1 + 5) } & 0x20 != 0 {
            break;
        }
        core::hint::spin_loop();
    }
    // SAFETY: writing the transmit holding register sends one byte.
    unsafe { outb(COM1, byte) };
}

/// Writes raw bytes, translating `\n` to `\r\n`.
pub fn write_bytes(bytes: &[u8]) {
    for &b in bytes {
        if b == b'\n' {
            put(b'\r');
        }
        put(b);
    }
}
