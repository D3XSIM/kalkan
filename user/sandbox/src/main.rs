//! An untrusted process.
//!
//! The sandbox image plays the attacker. The root task starts many instances of
//! it and tells each one which role to play:
//!
//! * the **main sandbox** ([`suite`]) holds only the four capabilities the root
//!   task granted it and tries to escalate its privileges, forge its identity,
//!   smuggle capabilities, exhaust kernel memory and finally read kernel memory;
//! * each **probe** ([`probes`]) performs one attack on the hardware-enforced
//!   boundary (privileged instructions, kernel memory, W^X, ...) that must get it
//!   killed — and only it — or plays its part in a process life-cycle test;
//! * the **fuzzer** ([`fuzz`]) throws tens of thousands of random system calls at
//!   the kernel.

#![no_std]
#![no_main]

mod fuzz;
mod probes;
mod suite;

use libkalkan::selftest::{self, mode, slot};
use libkalkan::{self as k};

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    k::set_console(slot::CONSOLE);
    // Ask the supervisor which role this instance plays.
    let Ok(role) = k::call(slot::ENDPOINT, [selftest::HELLO, 0, 0, 0], None) else {
        k::thread_exit(selftest::EXIT_CHECK_FAILED)
    };
    match role[0] {
        mode::MAIN => suite::run(role[1], role[2]),
        mode::FUZZ => fuzz::run(role[1]),
        other => probes::run(other, role[1]),
    }
}
