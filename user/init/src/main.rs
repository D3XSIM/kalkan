//! Kalkan root task.
//!
//! The first user process. It receives the initial capabilities from the kernel,
//! sets up an untrusted `sandbox` process with a minimal set of capabilities, and
//! runs an adversarial self-test suite: every test performs an operation that a
//! secure kernel **must refuse** (or must perform in a constrained way) and checks
//! that the kernel did exactly that.

#![no_std]
#![no_main]

use core::fmt::Display;

use libkalkan::selftest::{self, Expect, mode, slot as sb, vector};
use libkalkan::{self as k, Error, Rights, abi, abi::slot, println};

// Slots used by the root task.
const CONSOLE_W: u64 = slot::FIRST_FREE; // console, WRITE only
const ESCALATED: u64 = slot::FIRST_FREE + 1;
const FRAME: u64 = slot::FIRST_FREE + 2;
const FRAME_RO: u64 = slot::FIRST_FREE + 3;
const ENDPOINT: u64 = slot::FIRST_FREE + 4;
const FAULT_EP: u64 = slot::FIRST_FREE + 5;
const SHARED: u64 = slot::FIRST_FREE + 6;
const SCRATCH: u64 = slot::FIRST_FREE + 7;
const REVOKE_A: u64 = slot::FIRST_FREE + 8;
const REVOKE_B: u64 = slot::FIRST_FREE + 9;
const RECV: u64 = slot::FIRST_FREE + 10;
const SUB_UNTYPED: u64 = slot::FIRST_FREE + 11;
const ALIAS_A: u64 = slot::FIRST_FREE + 12;
const ALIAS_B: u64 = slot::FIRST_FREE + 13;
const PROBE_FAULT: u64 = slot::FIRST_FREE + 14;
const FUZZ_FRAME: u64 = slot::FIRST_FREE + 15;
const QUOTA_FIRST: u64 = 24;
const QUOTA_LAST: u64 = 63;
// Slots above the probe capabilities.
const PAGE_A: u64 = 200;
const PAGE_B: u64 = 201;
const LEAK: u64 = 204;

// Virtual addresses for test mappings.
const VA_FRAME: u64 = 0x0000_5000_0000_0000;
const VA_FRAME_RO: u64 = 0x0000_5000_0001_0000;
const VA_SHARED: u64 = 0x0000_5000_0002_0000;
const VA_ALIAS_W: u64 = 0x0000_5000_0003_0000;
const VA_ALIAS_X: u64 = 0x0000_5000_0004_0000;
const VA_PAIR: u64 = 0x0000_5000_0010_0000;
const VA_LEAK: u64 = 0x0000_3000_0000_0000;
const KERNEL_ADDR: u64 = 0xffff_8000_0000_0000;

struct Suite {
    passed: u32,
    failed: u32,
}

impl Suite {
    fn check(&mut self, name: &str, ok: bool, detail: impl Display) {
        if ok {
            self.passed += 1;
            println!("  [PASS] {name} ({detail})");
        } else {
            self.failed += 1;
            println!("  [FAIL] {name} ({detail})");
        }
    }

    fn expect_err<T>(&mut self, name: &str, result: k::Result<T>, expected: Error) {
        match result {
            Err(e) if e == expected => {
                self.check(name, true, format_args!("refused with {}", e.name()))
            }
            Err(e) => self.check(
                name,
                false,
                format_args!("got {}, expected {}", e.name(), expected.name()),
            ),
            Ok(_) => self.check(
                name,
                false,
                format_args!("ALLOWED, expected {}", expected.name()),
            ),
        }
    }

    fn expect_ok<T>(&mut self, name: &str, result: k::Result<T>) -> Option<T> {
        match result {
            Ok(v) => {
                self.check(name, true, "ok");
                Some(v)
            }
            Err(e) => {
                self.check(name, false, format_args!("failed with {}", e.name()));
                None
            }
        }
    }
}

fn section(title: &str) {
    println!("--- {title}");
}

fn capability_tests(s: &mut Suite) {
    section("capability enforcement");
    s.expect_err(
        "forged (empty) capability slot",
        k::debug_write(40, "x"),
        Error::EmptySlot,
    );
    s.expect_err(
        "out-of-range capability slot",
        k::debug_write(1 << 40, "x"),
        Error::BadSlot,
    );
    s.expect_err(
        "u64::MAX as capability slot",
        k::debug_write(u64::MAX, "x"),
        Error::BadSlot,
    );
    s.expect_err(
        "capability of the wrong type",
        k::debug_write(slot::UNTYPED, "x"),
        Error::WrongType,
    );
    // SAFETY: cap_mint cannot affect this program's memory.
    let undefined_bits = unsafe {
        k::syscall(
            abi::sys::CAP_MINT,
            [slot::CONSOLE, ESCALATED, 1 << 9, 0, 0, 0],
        )
    };
    s.expect_err(
        "undefined rights bits",
        undefined_bits.status(),
        Error::InvalidArgument,
    );
    s.expect_ok(
        "derive a WRITE-only console capability",
        k::cap_mint(slot::CONSOLE, CONSOLE_W, Rights::WRITE, 0),
    );
    s.expect_err(
        "rights escalation through mint",
        k::cap_mint(CONSOLE_W, ESCALATED, Rights::WRITE.union(Rights::GRANT), 0),
        Error::PermissionDenied,
    );
    let info = k::cap_info(CONSOLE_W);
    s.check(
        "derived capability carries only the requested rights",
        info.is_ok_and(|i| i.rights == Rights::WRITE),
        format_args!("{:?}", info.map(|i| i.rights)),
    );
    s.expect_err(
        "occupied destination slot",
        k::cap_mint(slot::CONSOLE, CONSOLE_W, Rights::WRITE, 0),
        Error::SlotOccupied,
    );
    // SAFETY: an unknown system call has no effect.
    let unknown = unsafe { k::syscall(999, [0; 6]) };
    s.expect_err("unknown system call number", unknown.status(), Error::NoSys);

    // Revocation reaches every descendant.
    let _ = k::cap_mint(
        slot::CONSOLE,
        REVOKE_A,
        Rights::WRITE.union(Rights::GRANT),
        0,
    );
    let _ = k::cap_mint(REVOKE_A, REVOKE_B, Rights::WRITE, 0);
    s.expect_ok("revoke a capability tree", k::cap_revoke(slot::CONSOLE));
    s.expect_err(
        "revoked grandchild capability is gone",
        k::cap_info(REVOKE_B),
        Error::EmptySlot,
    );
    s.expect_err(
        "revoked child capability is gone",
        k::debug_write(REVOKE_A, "x"),
        Error::EmptySlot,
    );
    s.check(
        "revoked parent itself survives",
        k::cap_info(slot::CONSOLE).is_ok(),
        "slot 4 intact",
    );
    let _ = k::cap_mint(slot::CONSOLE, CONSOLE_W, Rights::WRITE, 0);
}

fn pointer_tests(s: &mut Suite) {
    section("user/kernel boundary");
    let bad = |ptr: u64, len: u64| {
        // SAFETY: debug_write only reads; the kernel validates the pointer.
        unsafe { k::syscall(abi::sys::DEBUG_WRITE, [slot::CONSOLE, ptr, len, 0, 0, 0]) }.status()
    };
    s.expect_err(
        "kernel pointer passed to a system call",
        bad(KERNEL_ADDR, 16),
        Error::BadAddress,
    );
    s.expect_err(
        "kernel image pointer passed to a system call",
        bad(0xffff_ffff_8000_0000, 8),
        Error::BadAddress,
    );
    s.expect_err("null pointer", bad(0, 8), Error::BadAddress);
    s.expect_err(
        "pointer + length overflow",
        bad(u64::MAX - 3, 16),
        Error::BadAddress,
    );
    s.expect_err(
        "buffer straddling the canonical hole",
        bad(abi::USER_TOP - 4, 16),
        Error::BadAddress,
    );
    s.expect_err(
        "unmapped user memory",
        bad(0x0000_6000_0000_0000, 8),
        Error::BadAddress,
    );
    s.expect_err(
        "oversized buffer",
        bad(VA_FRAME, 1 << 20),
        Error::InvalidArgument,
    );
}

fn memory_tests(s: &mut Suite) {
    section("memory protection");
    s.expect_ok(
        "create a frame from the untyped budget",
        k::retype(slot::UNTYPED, abi::obj::FRAME, FRAME),
    );
    let rwx = Rights::READ.union(Rights::WRITE).union(Rights::EXEC);
    s.expect_err(
        "W+X mapping",
        k::vspace_map(slot::SELF_VSPACE, FRAME, VA_FRAME, rwx),
        Error::WxViolation,
    );
    let rw = Rights::READ.union(Rights::WRITE);
    s.expect_err(
        "mapping into the kernel half",
        k::vspace_map(slot::SELF_VSPACE, FRAME, KERNEL_ADDR, rw),
        Error::BadAddress,
    );
    s.expect_err(
        "unaligned mapping",
        k::vspace_map(slot::SELF_VSPACE, FRAME, VA_FRAME + 8, rw),
        Error::BadAddress,
    );
    s.expect_err(
        "mapping the null page",
        k::vspace_map(slot::SELF_VSPACE, FRAME, 0, rw),
        Error::BadAddress,
    );
    if s.expect_ok(
        "map frame read-write",
        k::vspace_map(slot::SELF_VSPACE, FRAME, VA_FRAME, rw),
    )
    .is_some()
    {
        // SAFETY: the page was just mapped read-write at VA_FRAME.
        let (zeroed, roundtrip) = unsafe {
            let p = VA_FRAME as *mut u64;
            let z = core::ptr::read_volatile(p) == 0;
            core::ptr::write_volatile(p, 0x6b61_6c6b_616e);
            (z, core::ptr::read_volatile(p) == 0x6b61_6c6b_616e)
        };
        s.check("new frames are zero-filled", zeroed, "no stale data");
        s.check("mapped frame is usable", roundtrip, "write/read round trip");
    }
    s.expect_err(
        "same frame capability mapped twice",
        k::vspace_map(slot::SELF_VSPACE, FRAME, VA_FRAME_RO, rw),
        Error::AlreadyMapped,
    );
    s.expect_ok(
        "derive a READ-only frame capability",
        k::cap_mint(FRAME, FRAME_RO, Rights::READ, 0),
    );
    s.expect_err(
        "writable mapping through a READ-only capability",
        k::vspace_map(slot::SELF_VSPACE, FRAME_RO, VA_FRAME_RO, rw),
        Error::PermissionDenied,
    );
    s.expect_err(
        "executable mapping through a capability without EXEC",
        k::vspace_map(
            slot::SELF_VSPACE,
            FRAME_RO,
            VA_FRAME_RO,
            Rights::READ.union(Rights::EXEC),
        ),
        Error::PermissionDenied,
    );
    s.expect_ok(
        "read-only mapping of the same frame",
        k::vspace_map(slot::SELF_VSPACE, FRAME_RO, VA_FRAME_RO, Rights::READ),
    );
    // SAFETY: both pages map the same frame.
    let shared = unsafe { core::ptr::read_volatile(VA_FRAME_RO as *const u64) } == 0x6b61_6c6b_616e;
    s.check(
        "read-only alias observes the same physical frame",
        shared,
        "aliasing is explicit",
    );

    // Revoking the original removes the derived capability *and its mapping*:
    // the address becomes free again.
    s.expect_ok("revoke the frame capability", k::cap_revoke(FRAME));
    s.expect_err(
        "derived frame capability deleted",
        k::cap_info(FRAME_RO),
        Error::EmptySlot,
    );
    let _ = k::retype(slot::UNTYPED, abi::obj::FRAME, SCRATCH);
    s.expect_ok(
        "revocation also removed the derived mapping",
        k::vspace_map(slot::SELF_VSPACE, SCRATCH, VA_FRAME_RO, Rights::READ),
    );
    let _ = k::cap_delete(SCRATCH);

    // W^X is enforced per frame, not just per mapping: a frame that is writable
    // through one capability cannot be made executable through an alias.
    let _ = k::retype(slot::UNTYPED, abi::obj::FRAME, ALIAS_A);
    let _ = k::cap_mint(ALIAS_A, ALIAS_B, Rights::ALL, 0);
    s.expect_ok(
        "map a frame writable",
        k::vspace_map(
            slot::SELF_VSPACE,
            ALIAS_A,
            VA_ALIAS_W,
            Rights::READ.union(Rights::WRITE),
        ),
    );
    s.expect_err(
        "W^X across aliases: same frame executable elsewhere",
        k::vspace_map(
            slot::SELF_VSPACE,
            ALIAS_B,
            VA_ALIAS_X,
            Rights::READ.union(Rights::EXEC),
        ),
        Error::WxViolation,
    );
    let _ = k::cap_delete(ALIAS_B);
    let _ = k::cap_delete(ALIAS_A);
    s.expect_err(
        "the null slot can never hold a capability",
        k::cap_mint(slot::CONSOLE, abi::slot::NULL, Rights::WRITE, 0),
        Error::BadSlot,
    );
}

fn quota_tests(s: &mut Suite) {
    section("resource accounting");
    let mut created = 0;
    let mut last = Ok(());
    for slot in QUOTA_FIRST..=QUOTA_LAST {
        last = k::retype(slot::UNTYPED, abi::obj::FRAME, slot);
        if last.is_err() {
            break;
        }
        created += 1;
    }
    s.check(
        "untyped budget is enforced",
        last == Err(Error::OutOfMemory),
        format_args!(
            "{created} frames created, then {:?}",
            last.err().map(Error::name)
        ),
    );
    for slot in QUOTA_FIRST..QUOTA_FIRST + created {
        let _ = k::cap_delete(slot);
    }
    s.expect_ok(
        "destroyed objects refund the budget",
        k::retype(slot::UNTYPED, abi::obj::FRAME, QUOTA_FIRST),
    );
    let _ = k::cap_delete(QUOTA_FIRST);

    // Page tables are bounded per address space: every mapping in a fresh 512 GiB
    // region needs three new tables, so the quota is hit long before the frame
    // budget (31 frames) runs out.
    let mut mapped = 0u64;
    let mut last = Ok(());
    for (i, slot) in (QUOTA_FIRST..=QUOTA_LAST).enumerate() {
        last = k::retype(slot::UNTYPED, abi::obj::FRAME, slot);
        if last.is_ok() {
            last = k::vspace_map(slot::SELF_VSPACE, slot, (i as u64 + 1) << 39, Rights::READ);
        }
        if last.is_err() {
            let _ = k::cap_delete(slot);
            break;
        }
        mapped += 1;
    }
    s.check(
        "page-table quota per address space",
        last == Err(Error::OutOfMemory) && mapped < 31,
        format_args!(
            "{mapped} sparse mappings, then {:?}",
            last.err().map(Error::name)
        ),
    );
    for slot in QUOTA_FIRST..QUOTA_FIRST + mapped {
        let _ = k::cap_delete(slot);
    }
    let again = k::retype(slot::UNTYPED, abi::obj::FRAME, QUOTA_FIRST)
        .and_then(|()| k::vspace_map(slot::SELF_VSPACE, QUOTA_FIRST, 1 << 39, Rights::READ));
    s.expect_ok("empty page tables are reclaimed on unmap", again);
    let _ = k::cap_delete(QUOTA_FIRST);

    // A delegated budget can be taken back together with everything built from it.
    s.expect_ok(
        "delegate a sub-budget",
        k::cap_mint(slot::UNTYPED, SUB_UNTYPED, Rights::WRITE, 0),
    );
    let _ = k::retype(SUB_UNTYPED, abi::obj::FRAME, QUOTA_FIRST);
    let _ = k::retype(SUB_UNTYPED, abi::obj::ENDPOINT, QUOTA_FIRST + 1);
    s.expect_ok("revoke the delegated budget", k::cap_revoke(SUB_UNTYPED));
    s.expect_err(
        "frame created from a revoked budget is destroyed",
        k::cap_info(QUOTA_FIRST),
        Error::EmptySlot,
    );
    s.expect_err(
        "endpoint created from a revoked budget is destroyed",
        k::cap_info(QUOTA_FIRST + 1),
        Error::EmptySlot,
    );
    let _ = k::cap_delete(SUB_UNTYPED);
}

/// Copies from user memory across page boundaries.
fn copy_tests(s: &mut Suite) {
    section("user memory copies");
    let rw = Rights::READ.union(Rights::WRITE);
    let text = b"KALKAN-CROSS-PAGE-COPY-OK";
    let start = VA_PAIR + 4096 - 12;
    let mapped = k::retype(slot::UNTYPED, abi::obj::FRAME, PAGE_A).is_ok()
        && k::retype(slot::UNTYPED, abi::obj::FRAME, PAGE_B).is_ok()
        && k::vspace_map(slot::SELF_VSPACE, PAGE_A, VA_PAIR, rw).is_ok()
        && k::vspace_map(slot::SELF_VSPACE, PAGE_B, VA_PAIR + 4096, rw).is_ok();
    if !mapped {
        s.check("map two adjacent pages", false, "setup failed");
        return;
    }
    // SAFETY: both pages were just mapped read-write; the text spans the boundary.
    unsafe { core::ptr::copy_nonoverlapping(text.as_ptr(), start as *mut u8, text.len()) };
    let write = |len: usize| {
        // SAFETY: debug_write only reads; the kernel validates the range.
        unsafe {
            k::syscall(
                abi::sys::DEBUG_WRITE,
                [slot::CONSOLE, start, len as u64, 0, 0, 0],
            )
        }
        .status()
    };
    s.expect_ok(
        "copy a buffer that crosses a page boundary",
        write(text.len()),
    );
    // Remove the second page: the same buffer must now be refused as a whole.
    let _ = k::cap_delete(PAGE_B);
    s.expect_err(
        "buffer whose second page was unmapped",
        write(text.len()),
        Error::BadAddress,
    );
    s.expect_ok(
        "the part on the remaining page is still readable",
        write(12),
    );
    let _ = k::cap_delete(PAGE_A);
    s.expect_err(
        "buffer on fully unmapped pages",
        write(12),
        Error::BadAddress,
    );
}

/// Kernel memory and object leaks, measured from the kernel's own counters.
fn leak_tests(s: &mut Suite) {
    section("kernel resource leaks");
    let rw = Rights::READ.union(Rights::WRITE);
    let cycle = |round: u64| {
        // A frame: create, map sparsely, alias through derived capabilities, revoke.
        let _ = k::retype(slot::UNTYPED, abi::obj::FRAME, LEAK);
        let _ = k::vspace_map(slot::SELF_VSPACE, LEAK, (round % 5 + 1) << 39, rw);
        for i in 1..4 {
            let _ = k::cap_mint(LEAK, LEAK + i, Rights::READ, 0);
            let _ = k::vspace_map(
                slot::SELF_VSPACE,
                LEAK + i,
                VA_LEAK + (i << 30),
                Rights::READ,
            );
        }
        let _ = k::cap_revoke(LEAK);
        let _ = k::cap_delete(LEAK);
        // An endpoint with badged copies.
        let _ = k::retype(slot::UNTYPED, abi::obj::ENDPOINT, LEAK);
        let _ = k::cap_mint(LEAK, LEAK + 1, Rights::WRITE, round + 1);
        let _ = k::cap_mint(LEAK + 1, LEAK + 2, Rights::WRITE, 0);
        let _ = k::cap_delete(LEAK + 1);
        let _ = k::cap_delete(LEAK);
        let _ = k::cap_delete(LEAK + 2);
        // A delegated budget that is revoked together with what it paid for.
        let _ = k::cap_mint(slot::UNTYPED, LEAK, Rights::WRITE, 0);
        let _ = k::retype(LEAK, abi::obj::FRAME, LEAK + 1);
        let _ = k::retype(LEAK, abi::obj::ENDPOINT, LEAK + 2);
        let _ = k::vspace_map(slot::SELF_VSPACE, LEAK + 1, VA_LEAK, rw);
        let _ = k::cap_revoke(LEAK);
        let _ = k::cap_delete(LEAK);
        // Failed operations must not leave anything behind either.
        let _ = k::retype(slot::UNTYPED, abi::obj::FRAME, slot::CONSOLE);
        let _ = k::retype(slot::UNTYPED, 99, LEAK);
        let _ = k::vspace_map(slot::SELF_VSPACE, LEAK, VA_LEAK, rw);
    };
    for round in 0..8 {
        cycle(round); // warm up: let the kernel's tables reach their steady size
    }
    let before = k::kernel_stats(slot::CONSOLE).ok();
    for round in 0..400 {
        cycle(round);
    }
    let after = k::kernel_stats(slot::CONSOLE).ok();
    s.check(
        "400 object life cycles leave no kernel memory or objects behind",
        no_growth(before, after),
        format_args!("{}", StatsLine(after.unwrap_or_default())),
    );
}

/// `true` if the kernel uses no more resources in `after` than in `before`.
fn no_growth(before: Option<k::KernelStats>, after: Option<k::KernelStats>) -> bool {
    match (before, after) {
        (Some(b), Some(a)) => {
            a.free_frames >= b.free_frames
                && a.heap_bytes <= b.heap_bytes
                && a.capabilities == b.capabilities
                && a.threads == b.threads
                && a.frames == b.frames
                && a.endpoints == b.endpoints
        }
        _ => false,
    }
}

struct StatsLine(k::KernelStats);

impl Display for StatsLine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = &self.0;
        write!(
            f,
            "{} frames free, {} heap bytes, {} capabilities, {} threads",
            s.free_frames, s.heap_bytes, s.capabilities, s.threads
        )
    }
}

/// Grants the sandbox exactly the capabilities it needs — and nothing else.
fn setup_sandbox(s: &mut Suite) -> bool {
    section("least-privilege sandbox setup");
    let ok = k::retype(slot::UNTYPED, abi::obj::ENDPOINT, ENDPOINT).is_ok()
        && k::cap_mint(ENDPOINT, FAULT_EP, Rights::WRITE, selftest::FAULT_BADGE).is_ok()
        && k::retype(slot::UNTYPED, abi::obj::FRAME, SHARED).is_ok()
        && k::vspace_map(
            slot::SELF_VSPACE,
            SHARED,
            VA_SHARED,
            Rights::READ.union(Rights::WRITE),
        )
        .is_ok();
    if !ok {
        s.check("create endpoint and shared frame", false, "setup failed");
        return false;
    }
    // SAFETY: VA_SHARED was just mapped read-write and is one page long.
    unsafe {
        let page = core::slice::from_raw_parts_mut(VA_SHARED as *mut u8, 4096);
        page.fill(b'.');
        page[..20].copy_from_slice(selftest::SHARED_SECRET);
        page[4096 - 16..].copy_from_slice(b"end-of-the-page!");
    }
    let t = slot::SANDBOX_THREAD;
    s.expect_err(
        "confinement: passing on a capability without GRANT",
        k::thread_grant(t, CONSOLE_W, sb::CONSOLE, Rights::WRITE, 0),
        Error::PermissionDenied,
    );
    let grants = [
        (
            "send-only badged endpoint",
            ENDPOINT,
            sb::ENDPOINT,
            Rights::WRITE,
            selftest::CLIENT_BADGE,
        ),
        (
            "write-only console",
            slot::CONSOLE,
            sb::CONSOLE,
            Rights::WRITE,
            0,
        ),
        (
            "read-only shared frame",
            SHARED,
            sb::SHARED_FRAME,
            Rights::READ,
            0,
        ),
        (
            "map right on its own address space",
            slot::SANDBOX_VSPACE,
            sb::VSPACE,
            Rights::WRITE,
            0,
        ),
    ];
    for (what, src, dst, rights, badge) in grants {
        let r = k::thread_grant(t, src, dst, rights, badge);
        s.check(what, r.is_ok(), format_args!("slot {dst}, rights {rights}"));
    }
    s.expect_err(
        "granting into the null slot",
        k::thread_grant(t, slot::CONSOLE, abi::slot::NULL, Rights::WRITE, 0),
        Error::BadSlot,
    );
    s.expect_ok(
        "route sandbox faults to the root task",
        k::thread_set_fault_ep(t, FAULT_EP),
    );
    s.expect_ok("start the sandbox", k::thread_start(t));
    s.expect_err(
        "a running thread cannot be started again",
        k::thread_start(t),
        Error::InvalidState,
    );
    true
}

/// What a supervised process did before it ended.
#[derive(Default)]
struct Served {
    passed: u32,
    failed: u32,
    wrong_badge: bool,
    marks: [Option<k::KernelStats>; 4],
    /// The kernel's final report: `[vector, error, address, rip]` for a fault,
    /// `[EXIT_VECTOR, code, 0, 0]` for an exit.
    end: [u64; 4],
}

/// Serves one supervised process until the kernel reports that it is gone.
///
/// With `noise` the process is a fuzzer: its messages are answered but their
/// contents mean nothing.
fn serve(
    client_badge: u64,
    fault_badge: u64,
    mode: u64,
    argument: u64,
    noise: bool,
) -> Option<Served> {
    let mut served = Served::default();
    loop {
        let msg = k::recv(ENDPOINT, Some(RECV)).ok()?;
        if msg.is_fault() {
            if msg.badge == fault_badge {
                served.end = msg.words;
                return Some(served);
            }
            served.wrong_badge = true;
            continue;
        }
        if msg.badge != client_badge {
            served.wrong_badge = true;
        }
        let reply = match msg.words[0] {
            selftest::HELLO => [mode, argument, 0, 0],
            _ if noise => [u64::MAX; 4],
            selftest::REPORT => {
                if msg.words[2] == 1 {
                    served.passed += 1;
                } else {
                    served.failed += 1;
                }
                [0; 4]
            }
            selftest::TRANSFER => [msg.info, 0, 0, 0],
            selftest::MARK => {
                if let Some(mark) = served.marks.get_mut(msg.words[1] as usize) {
                    *mark = k::kernel_stats(slot::CONSOLE).ok();
                }
                [0; 4]
            }
            selftest::DONE => [0; 4],
            _ => [u64::MAX; 4],
        };
        if msg.info & abi::msg::CAP_TRANSFERRED != 0 {
            let _ = k::cap_delete(RECV);
        }
        let _ = k::reply(reply);
    }
}

/// Runs the main sandbox and checks everything it reported.
fn run_sandbox(s: &mut Suite) {
    let Some(served) = serve(
        selftest::CLIENT_BADGE,
        selftest::FAULT_BADGE,
        mode::MAIN,
        0,
        false,
    ) else {
        s.check("serve the sandbox", false, "receive failed");
        return;
    };
    section("sandbox containment");
    let [vector, _, address, _] = served.end;
    s.check(
        "sandbox killed on its kernel memory access",
        vector == vector::PAGE_FAULT && address >= 0xffff_8000_0000_0000,
        format_args!("page fault at {address:#x}, reported with the fault badge"),
    );
    s.check(
        "every message carried the client's badge",
        !served.wrong_badge,
        "clients cannot forge identity",
    );
    s.check(
        "sandbox escape attempts all refused",
        served.failed == 0 && served.passed > 0,
        format_args!("{} checks passed, {} failed", served.passed, served.failed),
    );
    let [_, m1, m2, m3] = served.marks;
    s.check(
        "2000 map/unmap cycles by the sandbox leak nothing",
        no_growth(m1, m2),
        format_args!("{}", StatsLine(m2.unwrap_or_default())),
    );
    s.check(
        "hitting the page-table quota leaks nothing",
        no_growth(m1, m3),
        format_args!("{}", StatsLine(m3.unwrap_or_default())),
    );
    s.expect_err(
        "killed thread cannot be restarted",
        k::thread_start(slot::SANDBOX_THREAD),
        Error::Dead,
    );
    // Dropping the last capability to the dead sandbox's address space returns
    // its memory to the kernel.
    let before = k::kernel_stats(slot::CONSOLE).unwrap_or_default();
    let _ = k::cap_delete(slot::SANDBOX_VSPACE);
    let _ = k::cap_delete(slot::SANDBOX_THREAD);
    let after = k::kernel_stats(slot::CONSOLE).unwrap_or_default();
    s.check(
        "the dead sandbox's memory is reclaimed",
        after.free_frames > before.free_frames + 16,
        format_args!(
            "{} frames returned",
            after.free_frames.saturating_sub(before.free_frames)
        ),
    );
}

/// How a probe process ended, for the log.
struct Outcome([u64; 4]);

impl Display for Outcome {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let [vector, error, address, _] = self.0;
        match vector {
            abi::EXIT_VECTOR if error == selftest::EXIT_NOT_APPLICABLE => {
                f.write_str("not applicable: the CPU lacks the feature")
            }
            abi::EXIT_VECTOR if error == selftest::EXIT_ESCAPED => f.write_str("NOT STOPPED"),
            abi::EXIT_VECTOR => write!(f, "exited with {error:#x}"),
            vector::PAGE_FAULT => write!(f, "killed: page fault at {address:#x}, error {error:#x}"),
            vector::GENERAL_PROTECTION => f.write_str("killed: general protection fault"),
            vector::INVALID_OPCODE => f.write_str("killed: invalid opcode"),
            vector::DEVICE_NOT_AVAILABLE => f.write_str("killed: device not available"),
            vector::DIVIDE_ERROR => f.write_str("killed: divide error"),
            vector::DEBUG => f.write_str("killed: debug trap"),
            other => write!(f, "killed: exception {other}"),
        }
    }
}

/// Starts one probe process per attack and checks that each ends exactly as it
/// must — and that the kernel gets all of its resources back.
fn run_probes(s: &mut Suite) {
    section("fault containment: one process per attack");
    let rwx = Rights::READ.union(Rights::WRITE).union(Rights::EXEC);
    let (mut min_freed, mut max_freed) = (u64::MAX, 0);
    let mut clean = true;
    for (i, probe) in selftest::PROBES.iter().enumerate() {
        let i = i as u64;
        let thread = slot::PROBE_THREAD_FIRST + i;
        let (client, fault) = (
            selftest::PROBE_CLIENT_BADGE + i,
            selftest::PROBE_FAULT_BADGE + i,
        );
        let before = k::kernel_stats(slot::CONSOLE).unwrap_or_default();

        let mut ready = k::thread_grant(thread, ENDPOINT, sb::ENDPOINT, Rights::WRITE, client)
            .is_ok()
            && k::thread_grant(thread, slot::CONSOLE, sb::CONSOLE, Rights::WRITE, 0).is_ok()
            && k::cap_mint(ENDPOINT, PROBE_FAULT, Rights::WRITE, fault).is_ok()
            && k::thread_set_fault_ep(thread, PROBE_FAULT).is_ok();
        let _ = k::cap_delete(PROBE_FAULT);
        let mut argument = 0;
        if probe.mode == mode::FUZZ {
            // The fuzzer gets real capabilities so that its calls reach deep into
            // the kernel: a private frame, its address space, a memory budget.
            argument = k::random();
            println!("  fuzzer seed: {argument:#x}");
            ready &= k::retype(slot::UNTYPED, abi::obj::FRAME, FUZZ_FRAME).is_ok()
                && k::thread_grant(thread, FUZZ_FRAME, sb::SHARED_FRAME, rwx, 0).is_ok()
                && k::thread_grant(
                    thread,
                    slot::PROBE_VSPACE_FIRST + i,
                    sb::VSPACE,
                    Rights::WRITE,
                    0,
                )
                .is_ok()
                && k::thread_grant(thread, slot::UNTYPED, sb::FUZZ_UNTYPED, Rights::WRITE, 0)
                    .is_ok();
        }
        ready &= k::thread_start(thread).is_ok();
        let served = if ready {
            serve(
                client,
                fault,
                probe.mode,
                argument,
                probe.mode == mode::FUZZ,
            )
        } else {
            None
        };
        let _ = k::cap_delete(FUZZ_FRAME);
        // An address space lives as long as a capability refers to it: dropping
        // ours lets the kernel reclaim the dead process's memory.
        let _ = k::cap_delete(slot::PROBE_VSPACE_FIRST + i);
        let _ = k::cap_delete(thread);
        let Some(served) = served else {
            s.check(probe.name, false, "could not run the probe");
            continue;
        };

        let [vector, error, ..] = served.end;
        let exited = |code: u64| vector == abi::EXIT_VECTOR && error == code;
        let as_expected = match probe.expect {
            Expect::Fault {
                vector: v,
                error_bits,
            } => vector == v && error & error_bits == error_bits,
            Expect::FaultEither(a, b) => vector == a || vector == b,
            Expect::FaultOrNotApplicable(v) => vector == v || exited(selftest::EXIT_NOT_APPLICABLE),
            Expect::Exit(code) => exited(code),
        };
        s.check(
            probe.name,
            as_expected && !served.wrong_badge,
            Outcome(served.end),
        );

        // The dead process must have given everything back.
        let after = k::kernel_stats(slot::CONSOLE).unwrap_or_default();
        let freed = after.free_frames.saturating_sub(before.free_frames);
        // (The fuzzer makes the kernel's tables grow to their working size, so its
        // memory balance is not comparable.)
        let fuzzer = probe.mode == mode::FUZZ;
        if !fuzzer {
            min_freed = min_freed.min(freed);
            max_freed = max_freed.max(freed);
        }
        clean &= after.threads + 1 == before.threads
            && after.capabilities + 2 == before.capabilities
            && after.endpoints == before.endpoints
            && after.frames == before.frames
            && (fuzzer || after.heap_bytes < before.heap_bytes);
    }
    s.check(
        "every terminated process returned all of its kernel objects",
        clean,
        "threads, capabilities, endpoints, frames, heap",
    );
    s.check(
        "every terminated process returned its memory",
        min_freed > 16 && max_freed - min_freed <= 8,
        format_args!("{min_freed}..{max_freed} frames each"),
    );
    let end = k::kernel_stats(slot::CONSOLE).unwrap_or_default();
    s.check(
        "only the root task is left",
        end.threads == 1 && end.endpoints == 1,
        format_args!("{}", StatsLine(end)),
    );
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    k::set_console(slot::CONSOLE);
    println!(
        "Kalkan root task running at {:#x} (randomised)",
        _start as *const () as usize
    );
    println!("Running the adversarial security test suite...");
    let mut s = Suite {
        passed: 0,
        failed: 0,
    };
    capability_tests(&mut s);
    pointer_tests(&mut s);
    memory_tests(&mut s);
    copy_tests(&mut s);
    quota_tests(&mut s);
    leak_tests(&mut s);
    if setup_sandbox(&mut s) {
        run_sandbox(&mut s);
        run_probes(&mut s);
    }
    println!("==================================================================");
    if s.failed == 0 {
        println!("KALKAN-TEST: PASS - all {} security tests passed", s.passed);
    } else {
        println!(
            "KALKAN-TEST: FAIL - {} of {} security tests failed",
            s.failed,
            s.passed + s.failed
        );
    }
    println!("==================================================================");
    k::thread_exit(u64::from(s.failed))
}
