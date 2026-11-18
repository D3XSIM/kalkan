//! System call fuzzer.
//!
//! Issues tens of thousands of system calls with adversarial arguments: random
//! numbers, boundary values, kernel addresses, sparse user addresses and the slot
//! numbers of capabilities the process really holds (so the calls reach deep into
//! the kernel instead of bouncing off the first check).
//!
//! The fuzzer has no oracle of its own. The test run enables the kernel's `audit`
//! feature, so after **every** call the kernel re-verifies its entire object graph
//! (reference counts, capability derivation tree, page tables, budgets, queues);
//! any inconsistency, kernel panic or hang fails the run.

use libkalkan::selftest::{self, slot};
use libkalkan::{self as k, abi};

const ITERATIONS: u32 = 24_000;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

const INTERESTING: [u64; 40] = [
    0,
    1,
    2,
    7,
    8,
    9,
    15,
    16,
    63,
    64,
    127,
    128,
    255,
    256,
    257,
    4095,
    4096,
    4097,
    0x1f_ffff,
    0x20_0000,
    1 << 30,
    1 << 31,
    1 << 32,
    1 << 39,
    1 << 47,
    abi::USER_BOTTOM - 4096,
    abi::USER_BOTTOM,
    abi::USER_TOP - 4096,
    abi::USER_TOP - 1,
    abi::USER_TOP,
    0x0000_7fff_ffff_f000,
    0x0000_8000_0000_0000,
    0xffff_8000_0000_0000,
    0xffff_ffff_8000_0000,
    0xffff_ffff_ffff_f000,
    u64::MAX - 1,
    u64::MAX,
    i64::MAX as u64,
    1 << 63,
    abi::NO_CAP,
];

fn argument(rng: &mut Rng, stack: u64) -> u64 {
    match rng.below(12) {
        // Small numbers: capability slots, rights bits, object types.
        0..=4 => rng.below(20),
        5 | 6 => INTERESTING[rng.below(INTERESTING.len() as u64) as usize],
        // Page-aligned user addresses, dense and sparse.
        7 => abi::USER_BOTTOM + (rng.below(64) << 12),
        8 => (rng.below(200) + 1) << (12 + 9 * rng.below(4)),
        // Addresses inside this program's own stack.
        9 => stack.wrapping_sub(rng.below(8192)),
        10 => rng.below(256),
        _ => rng.next(),
    }
}

/// `true` if `slot` holds an endpoint on which this process could block forever
/// (one it created itself — nobody else will ever send or receive on it).
fn would_block(slot_nr: u64, own_badge: u64) -> bool {
    k::cap_info(slot_nr)
        .is_ok_and(|info| info.obj_type == abi::obj::ENDPOINT && info.badge != own_badge)
}

pub fn run(seed: u64) -> ! {
    let marker = 0u8;
    let stack = &raw const marker as u64;
    let own_badge = k::cap_info(slot::ENDPOINT).map_or(u64::MAX, |i| i.badge);
    let mut rng = Rng(seed | 1);
    let mut errors = [0u32; 16];
    let mut successes = 0u32;

    for _ in 0..ITERATIONS {
        let nr = match rng.below(32) {
            n @ 0..=18 => n,
            // Extra weight on the calls with the most kernel state behind them.
            19 | 20 => abi::sys::CAP_MINT,
            21 => abi::sys::CAP_DELETE,
            22 => abi::sys::CAP_REVOKE,
            23 | 24 => abi::sys::UNTYPED_RETYPE,
            25 | 26 => abi::sys::VSPACE_MAP,
            27 => abi::sys::VSPACE_UNMAP,
            28 => abi::sys::DEBUG_WRITE,
            29 => abi::sys::EP_CALL,
            _ => rng.next(),
        };
        let mut a = [0u64; 6];
        for arg in &mut a {
            *arg = argument(&mut rng, stack);
        }
        // Steer a share of the calls at capabilities that really exist.
        if rng.below(3) == 0 {
            a[0] = [
                slot::ENDPOINT,
                slot::CONSOLE,
                slot::SHARED_FRAME,
                slot::VSPACE,
                slot::FUZZ_UNTYPED,
            ][rng.below(5) as usize];
        }
        match nr {
            abi::sys::THREAD_EXIT => continue,
            // Keep the two capabilities needed to report the result.
            abi::sys::CAP_DELETE if a[0] == slot::ENDPOINT || a[0] == slot::CONSOLE => continue,
            abi::sys::EP_SEND | abi::sys::EP_CALL | abi::sys::EP_RECV
                if would_block(a[0], own_badge) =>
            {
                continue;
            }
            // Keep the console readable: only tiny writes may succeed.
            abi::sys::DEBUG_WRITE if a[2] > 24 && a[2] <= 4096 => a[2] = rng.below(24),
            _ => {}
        }
        // SAFETY: the kernel validates every argument. The calls cannot unmap or
        // change memory this program uses: it holds no capability to its own
        // image or stack frames.
        let status = unsafe { k::syscall(nr, a) }.rax;
        match status {
            0 => successes += 1,
            e if e < errors.len() as u64 => errors[e as usize] += 1,
            // Anything that is neither success nor a defined error code is a bug.
            _ => k::thread_exit(selftest::EXIT_CHECK_FAILED | 0xf0),
        }
    }

    // The process must still be fully functional after all that.
    k::set_console(slot::CONSOLE);
    k::println!(
        "  fuzzer: {ITERATIONS} system calls, {successes} succeeded, errors by code {:?}",
        &errors[1..=13]
    );
    let _ = k::call(
        slot::ENDPOINT,
        [selftest::DONE, u64::from(ITERATIONS), 0, 0],
        None,
    );
    k::thread_exit(selftest::EXIT_OK)
}
