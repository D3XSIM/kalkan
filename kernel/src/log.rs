//! Kernel log on the serial console.

use core::fmt::{self, Write};

use crate::arch::serial;
use crate::sync::SpinLock;

struct Serial;

impl Write for Serial {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        serial::write_bytes(s.as_bytes());
        Ok(())
    }
}

static LOG: SpinLock<()> = SpinLock::new(());

#[doc(hidden)]
pub fn _print(args: fmt::Arguments<'_>) {
    let _guard = LOG.lock();
    let _ = Serial.write_fmt(args);
}

/// Prints even if the log lock is held (panic path only).
pub fn print_force(args: fmt::Arguments<'_>) {
    let _ = Serial.write_fmt(args);
}

/// Writes bytes that originate from user space.
///
/// Untrusted output is sanitised: only printable ASCII, newline and tab pass
/// through; everything else (including ESC) is replaced by `?`. A process can
/// therefore never inject terminal escape sequences into the operator's console
/// or forge kernel log lines.
pub fn write_untrusted(prefix: &str, bytes: &[u8]) {
    let _guard = LOG.lock();
    let mut line_start = true;
    for &b in bytes {
        if line_start {
            serial::write_bytes(prefix.as_bytes());
            line_start = false;
        }
        let c = match b {
            b'\n' => {
                line_start = true;
                b'\n'
            }
            b'\t' | 0x20..=0x7e => b,
            _ => b'?',
        };
        serial::write_bytes(&[c]);
    }
    if !line_start {
        serial::write_bytes(b"\n");
    }
}

/// Prints to the kernel log.
#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => { $crate::log::_print(format_args!($($arg)*)) };
}

/// Prints a line to the kernel log.
#[macro_export]
macro_rules! kprintln {
    () => { $crate::kprint!("\n") };
    ($($arg:tt)*) => { $crate::log::_print(format_args!("{}\n", format_args!($($arg)*))) };
}
