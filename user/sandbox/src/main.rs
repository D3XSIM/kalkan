//! An untrusted process.
//!
//! The sandbox plays the attacker. It holds only the four capabilities the root
//! task granted it and actively tries to escalate its privileges, forge its
//! identity, smuggle capabilities, write to read-only memory and finally read
//! kernel memory. Every attempt must fail; each result is reported to the root
//! task over IPC. Its last act is fatal by design: the kernel kills it and sends a
//! fault report to the root task.

#![no_std]
#![no_main]

use libkalkan::selftest::{self, slot};
use libkalkan::{self as k, Error, Rights, abi, println};

const VA_SHARED: u64 = 0x0000_4000_0000_0000;
const VA_SHARED_X: u64 = 0x0000_4000_0001_0000;
const VA_CYCLE: u64 = 0x0000_2000_0000_0000;

struct Attacker {
    id: u64,
}

impl Attacker {
    fn send(&mut self, passed: bool) {
        self.id += 1;
        let _ = k::call(
            slot::ENDPOINT,
            [selftest::REPORT, self.id, u64::from(passed), 0],
            None,
        );
    }

    /// An attack: `blocked` means the kernel stopped it.
    fn report(&mut self, name: &str, blocked: bool, detail: &str) {
        let tag = if blocked { "BLOCKED" } else { "ESCAPED" };
        println!("  [{tag}] {name} ({detail})");
        self.send(blocked);
    }

    /// A legitimate operation that must keep working inside the sandbox.
    fn report_allowed(&mut self, name: &str, works: bool, detail: &str) {
        let tag = if works { "ALLOWED" } else { "BROKEN" };
        println!("  [{tag}] {name} ({detail})");
        self.send(works);
    }

    fn expect<T>(&mut self, name: &str, result: k::Result<T>, expected: Error) {
        match result {
            Err(e) if e == expected => self.report(name, true, e.name()),
            Err(e) => self.report(name, false, e.name()),
            Ok(_) => self.report(name, false, "operation succeeded"),
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    k::set_console(slot::CONSOLE);
    println!(
        "sandbox started at {:#x} with 4 capabilities; attempting to escape...",
        _start as *const () as usize
    );
    let mut a = Attacker { id: 0 };

    // 1. Ambient authority does not exist: the root task's slot numbers mean
    //    nothing here.
    a.expect(
        "use the root task's console slot",
        k::debug_write(abi::slot::CONSOLE, "x"),
        Error::EmptySlot,
    );
    a.expect(
        "allocate memory without an untyped capability",
        k::retype(abi::slot::UNTYPED, abi::obj::FRAME, slot::FIRST_FREE),
        Error::EmptySlot,
    );
    a.expect(
        "start a thread it has no capability to",
        k::thread_start(abi::slot::SANDBOX_THREAD),
        Error::EmptySlot,
    );

    // 2. Privilege escalation through capability derivation.
    a.expect(
        "add GRANT to its console capability",
        k::cap_mint(
            slot::CONSOLE,
            slot::FIRST_FREE,
            Rights::WRITE.union(Rights::GRANT),
            0,
        ),
        Error::PermissionDenied,
    );
    a.expect(
        "add READ to its send-only endpoint",
        k::cap_mint(
            slot::ENDPOINT,
            slot::FIRST_FREE,
            Rights::READ.union(Rights::WRITE),
            0,
        ),
        Error::PermissionDenied,
    );
    a.expect(
        "forge a different badge (identity spoofing)",
        k::cap_mint(slot::ENDPOINT, slot::FIRST_FREE, Rights::WRITE, 0x1),
        Error::InvalidArgument,
    );
    a.expect(
        "receive on a send-only endpoint",
        k::recv(slot::ENDPOINT, None),
        Error::PermissionDenied,
    );
    a.expect(
        "inspect the kernel via a bogus syscall",
        unsafe_raw(u64::MAX),
        Error::NoSys,
    );

    // 3. Capability smuggling: the console capability lacks GRANT, so IPC must
    //    refuse to transfer it.
    let reply = k::call(
        slot::ENDPOINT,
        [selftest::TRANSFER, 0, 0, 0],
        Some(slot::CONSOLE),
    );
    let refused = reply
        .is_ok_and(|r| r[0] & abi::msg::CAP_REFUSED != 0 && r[0] & abi::msg::CAP_TRANSFERRED == 0);
    a.report(
        "smuggle a non-grantable capability over IPC",
        refused,
        "transfer refused by the kernel",
    );

    // 4. Kernel memory exhaustion through page tables: map and unmap a frame at
    //    2000 fresh addresses (each would need new page tables). Empty tables must
    //    be reclaimed, so this keeps working and costs the kernel nothing.
    let mut cycles = 0;
    for i in 0..2000u64 {
        let va = VA_CYCLE + (i << 30);
        if k::vspace_map(slot::VSPACE, slot::SHARED_FRAME, va, Rights::READ).is_err() {
            break;
        }
        // SAFETY: nothing references the page that is unmapped.
        if unsafe { k::vspace_unmap(slot::SHARED_FRAME) }.is_err() {
            break;
        }
        cycles += 1;
    }
    a.report(
        "exhaust kernel memory by map/unmap cycling",
        cycles == 2000,
        "page tables reclaimed, quota never hit",
    );

    // 5. Memory: the shared frame is read-only for us.
    let rw = Rights::READ.union(Rights::WRITE);
    a.expect(
        "map the read-only shared frame writable",
        k::vspace_map(slot::VSPACE, slot::SHARED_FRAME, VA_SHARED, rw),
        Error::PermissionDenied,
    );
    a.expect(
        "map the shared frame executable",
        k::vspace_map(
            slot::VSPACE,
            slot::SHARED_FRAME,
            VA_SHARED_X,
            Rights::READ.union(Rights::EXEC),
        ),
        Error::PermissionDenied,
    );
    match k::vspace_map(slot::VSPACE, slot::SHARED_FRAME, VA_SHARED, Rights::READ) {
        Ok(()) => {
            // SAFETY: the page was just mapped read-only.
            let data = unsafe { core::slice::from_raw_parts(VA_SHARED as *const u8, 20) };
            let ok = data == selftest::SHARED_SECRET;
            println!(
                "  read-only shared memory says: {:?}",
                core::str::from_utf8(data).unwrap_or("?")
            );
            a.report_allowed("read-only sharing works as granted", ok, "contents match");
        }
        Err(e) => a.report_allowed("read-only sharing works as granted", false, e.name()),
    }
    a.expect(
        "map memory over the kernel",
        k::vspace_map(
            slot::VSPACE,
            slot::SHARED_FRAME,
            0xffff_ffff_8000_0000,
            Rights::READ,
        ),
        Error::BadAddress,
    );
    a.expect(
        "make the kernel read kernel memory for us",
        // SAFETY: debug_write only reads, and the kernel validates the pointer.
        unsafe {
            k::syscall(
                abi::sys::DEBUG_WRITE,
                [slot::CONSOLE, 0xffff_ffff_8000_0000, 64, 0, 0, 0],
            )
        }
        .status(),
        Error::BadAddress,
    );
    println!(
        "  [INFO] terminal escape injection attempt follows: \x1b[2J\x1b[31mFAKE KERNEL LOG\x1b[0m"
    );

    let _ = k::call(slot::ENDPOINT, [selftest::DONE, a.id, 0, 0], None);

    // 6. Finally, read kernel memory directly. The MMU must stop this (supervisor
    //    page) and the kernel must kill us and notify our supervisor.
    println!("  reading kernel memory at 0xffffffff80000000 ...");
    // SAFETY: this is the attack — it is *expected* to fault.
    let leaked = unsafe { core::ptr::read_volatile(0xffff_ffff_8000_0000 as *const u64) };
    println!("  [ESCAPED] read kernel memory: {leaked:#x}");
    k::thread_exit(1)
}

fn unsafe_raw(nr: u64) -> k::Result<()> {
    // SAFETY: an unknown system call has no effect.
    unsafe { k::syscall(nr, [0; 6]) }.status()
}
