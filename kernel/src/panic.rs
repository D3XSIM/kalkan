//! Panic handler: fail closed.
//!
//! A kernel panic means an invariant was violated. The kernel never tries to
//! recover: it reports the error and stops the machine, so a corrupted kernel can
//! never keep running user code.

use core::panic::PanicInfo;

use crate::{arch, log};

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    arch::disable_interrupts();
    log::print_force(format_args!(
        "\n\x1b[1;31m!!! KERNEL PANIC !!!\x1b[0m\n{info}\n"
    ));
    log::print_force(format_args!("System halted (fail-closed).\n"));
    arch::shutdown(false)
}
