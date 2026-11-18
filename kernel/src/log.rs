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

/// An address in a kernel log line.
///
/// Test kernels (feature `selftest`) print it; every other kernel prints
/// `<hidden>`. The console may be captured, shared or readable by others, and an
/// address on it would give away the KASLR slide or the layout of an address
/// space. (Panic messages still print addresses: the system halts right after,
/// and the next boot is randomised afresh.)
#[derive(Clone, Copy, Debug)]
pub struct Addr(pub u64);

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if cfg!(feature = "selftest") {
            write!(f, "{:#x}", self.0)
        } else {
            f.write_str("<hidden>")
        }
    }
}

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
