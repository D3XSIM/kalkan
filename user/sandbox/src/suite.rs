//! The main sandbox: every non-fatal way out we could think of.
//!
//! It holds exactly four capabilities — a send-only badged endpoint, a write-only
//! console, a read-only frame and the right to map into its own address space —
//! and reports the outcome of every attempt to the root task over IPC. Its last
//! act is fatal by design: it reads kernel memory, the kernel kills it and sends
//! a fault report to the root task.

use libkalkan::selftest::{self, slot};
use libkalkan::{self as k, Error, Rights, abi, println};

const VA_SHARED: u64 = 0x0000_4000_0000_0000;
const VA_SHARED_X: u64 = 0x0000_4000_0001_0000;
const VA_CYCLE: u64 = 0x0000_2000_0000_0000;
const KERNEL_IMAGE: u64 = 0xffff_ffff_8000_0000;
/// First slot of the scratch range used by the capability table tests.
const SCRATCH: u64 = slot::FIRST_FREE;
const LAST_SLOT: u64 = abi::CSPACE_SLOTS as u64 - 1;

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

fn raw(nr: u64, args: [u64; 6]) -> k::Result<()> {
    // SAFETY: none of the calls made through this helper can unmap or change
    // memory this program uses; the kernel validates every argument.
    unsafe { k::syscall(nr, args) }.status()
}

fn write_raw(ptr: u64, len: u64) -> k::Result<()> {
    raw(abi::sys::DEBUG_WRITE, [slot::CONSOLE, ptr, len, 0, 0, 0])
}

/// Ambient authority does not exist: the root task's slot numbers mean nothing here.
fn ambient_authority(a: &mut Attacker) {
    a.expect(
        "use the root task's console slot",
        k::debug_write(abi::slot::CONSOLE, "x"),
        Error::EmptySlot,
    );
    a.expect(
        "allocate memory without an untyped capability",
        k::retype(abi::slot::UNTYPED, abi::obj::FRAME, SCRATCH),
        Error::EmptySlot,
    );
    a.expect(
        "start a thread it has no capability to",
        k::thread_start(abi::slot::SANDBOX_THREAD),
        Error::EmptySlot,
    );
    a.expect(
        "use the root task's probe thread capabilities",
        k::thread_start(abi::slot::PROBE_THREAD_FIRST),
        Error::EmptySlot,
    );
    a.expect(
        "read kernel statistics with a write-only console",
        k::kernel_stats(slot::CONSOLE),
        Error::PermissionDenied,
    );
}

/// Privilege escalation through capability derivation.
fn escalation(a: &mut Attacker) {
    let rw = Rights::READ.union(Rights::WRITE);
    a.expect(
        "add GRANT to its console capability",
        k::cap_mint(
            slot::CONSOLE,
            SCRATCH,
            Rights::WRITE.union(Rights::GRANT),
            0,
        ),
        Error::PermissionDenied,
    );
    a.expect(
        "add READ to its console capability",
        k::cap_mint(slot::CONSOLE, SCRATCH, rw, 0),
        Error::PermissionDenied,
    );
    a.expect(
        "add READ to its send-only endpoint",
        k::cap_mint(slot::ENDPOINT, SCRATCH, rw, 0),
        Error::PermissionDenied,
    );
    a.expect(
        "add WRITE to its read-only frame",
        k::cap_mint(slot::SHARED_FRAME, SCRATCH, rw, 0),
        Error::PermissionDenied,
    );
    a.expect(
        "forge a different badge (identity spoofing)",
        k::cap_mint(slot::ENDPOINT, SCRATCH, Rights::WRITE, 0x1),
        Error::InvalidArgument,
    );
    a.expect(
        "use undefined rights bits",
        raw(abi::sys::CAP_MINT, [slot::CONSOLE, SCRATCH, 0x10, 0, 0, 0]),
        Error::InvalidArgument,
    );
    a.expect(
        "mint into the null slot",
        k::cap_mint(slot::CONSOLE, abi::slot::NULL, Rights::WRITE, 0),
        Error::BadSlot,
    );
    a.expect(
        "mint a capability onto itself",
        k::cap_mint(slot::CONSOLE, slot::CONSOLE, Rights::WRITE, 0),
        Error::SlotOccupied,
    );
    a.expect(
        "mint from an empty slot",
        k::cap_mint(SCRATCH, SCRATCH + 1, Rights::NONE, 0),
        Error::EmptySlot,
    );
    a.expect(
        "mint beyond the capability space",
        k::cap_mint(slot::CONSOLE, LAST_SLOT + 1, Rights::WRITE, 0),
        Error::BadSlot,
    );
}

/// IPC state machine abuse.
fn ipc_abuse(a: &mut Attacker) {
    a.expect(
        "receive on a send-only endpoint",
        k::recv(slot::ENDPOINT, None),
        Error::PermissionDenied,
    );
    a.expect(
        "reply without a pending call",
        k::reply([0; 4]),
        Error::InvalidState,
    );
    a.expect(
        "send on a capability that is not an endpoint",
        k::send(slot::CONSOLE, [0; 4], None),
        Error::WrongType,
    );
    a.expect(
        "send on an empty slot",
        k::send(SCRATCH, [0; 4], None),
        Error::EmptySlot,
    );
    a.expect(
        "call a slot far outside the table",
        k::call(1 << 40, [0; 4], None),
        Error::BadSlot,
    );
    a.expect(
        "issue an undefined system call",
        raw(u64::MAX, [0; 6]),
        Error::NoSys,
    );
    a.expect(
        "issue the first undefined system call number",
        raw(abi::sys::COUNT, [0; 6]),
        Error::NoSys,
    );

    // Capability smuggling: nothing the sandbox holds carries GRANT, so IPC must
    // refuse every transfer — whatever slot is named.
    for (what, cap) in [
        ("its console capability", slot::CONSOLE),
        ("its endpoint capability", slot::ENDPOINT),
        ("its frame capability", slot::SHARED_FRAME),
        ("the null slot", abi::slot::NULL),
        ("an empty slot", SCRATCH),
        ("an out-of-range slot", 1 << 40),
    ] {
        let reply = k::call(slot::ENDPOINT, [selftest::TRANSFER, 0, 0, 0], Some(cap));
        let refused = reply.is_ok_and(|r| {
            r[0] & abi::msg::CAP_REFUSED != 0 && r[0] & abi::msg::CAP_TRANSFERRED == 0
        });
        a.report("smuggle a capability over IPC", refused, what);
    }
}

/// Abuse of its own capability table.
fn capability_table(a: &mut Attacker) {
    a.expect(
        "delete an empty slot",
        k::cap_delete(SCRATCH),
        Error::EmptySlot,
    );
    a.expect(
        "revoke an empty slot",
        k::cap_revoke(SCRATCH),
        Error::EmptySlot,
    );
    a.expect(
        "delete beyond the capability space",
        k::cap_delete(LAST_SLOT + 1),
        Error::BadSlot,
    );
    a.expect(
        "inspect the null slot",
        k::cap_info(abi::slot::NULL),
        Error::EmptySlot,
    );

    // Fill every free slot. The number of capabilities a process can create is
    // bounded by its capability space, so it cannot exhaust the kernel's table.
    let mut filled = 0;
    for s in SCRATCH..=LAST_SLOT {
        if k::cap_mint(slot::CONSOLE, s, Rights::WRITE, 0).is_ok() {
            filled += 1;
        }
    }
    let bounded = filled == LAST_SLOT - SCRATCH + 1
        && k::cap_mint(slot::CONSOLE, LAST_SLOT, Rights::WRITE, 0) == Err(Error::SlotOccupied);
    a.report(
        "flood the capability table",
        bounded,
        "bounded by its own capability space",
    );
    // One revocation removes all of them...
    let revoked = k::cap_revoke(slot::CONSOLE).is_ok()
        && (SCRATCH..=LAST_SLOT).all(|s| k::cap_info(s) == Err(Error::EmptySlot));
    a.report_allowed(
        "revoke its own derived capabilities",
        revoked,
        "all copies gone",
    );

    // ...and it also reaches the far end of a maximally deep derivation chain.
    let mut depth = 0;
    let mut parent = slot::CONSOLE;
    for s in SCRATCH..=LAST_SLOT {
        if k::cap_mint(parent, s, Rights::WRITE, 0).is_err() {
            break;
        }
        parent = s;
        depth += 1;
    }
    let chain_gone = k::cap_revoke(SCRATCH).is_ok()
        && k::cap_info(SCRATCH).is_ok()
        && (SCRATCH + 1..=LAST_SLOT).all(|s| k::cap_info(s) == Err(Error::EmptySlot));
    a.report_allowed(
        "revoke a deep derivation chain",
        chain_gone && depth == LAST_SLOT - SCRATCH + 1,
        "every descendant removed",
    );
    let _ = k::cap_delete(SCRATCH);
}

/// Memory: the shared frame is read-only for us.
fn memory(a: &mut Attacker) {
    let rw = Rights::READ.union(Rights::WRITE);
    let rx = Rights::READ.union(Rights::EXEC);
    a.expect(
        "map the read-only shared frame writable",
        k::vspace_map(slot::VSPACE, slot::SHARED_FRAME, VA_SHARED, rw),
        Error::PermissionDenied,
    );
    a.expect(
        "map the shared frame executable",
        k::vspace_map(slot::VSPACE, slot::SHARED_FRAME, VA_SHARED_X, rx),
        Error::PermissionDenied,
    );
    a.expect(
        "request a writable and executable mapping",
        k::vspace_map(
            slot::VSPACE,
            slot::SHARED_FRAME,
            VA_SHARED,
            Rights::ALL.intersect(rw.union(rx)),
        ),
        Error::WxViolation,
    );
    a.expect(
        "map memory over the kernel",
        k::vspace_map(slot::VSPACE, slot::SHARED_FRAME, KERNEL_IMAGE, Rights::READ),
        Error::BadAddress,
    );
    a.expect(
        "map memory at a non-canonical address",
        k::vspace_map(
            slot::VSPACE,
            slot::SHARED_FRAME,
            0x0000_8000_0000_0000,
            Rights::READ,
        ),
        Error::BadAddress,
    );
    a.expect(
        "map the last page below the canonical hole",
        k::vspace_map(
            slot::VSPACE,
            slot::SHARED_FRAME,
            0x0000_7fff_ffff_f000,
            Rights::READ,
        ),
        Error::BadAddress,
    );
    a.expect(
        "map through a capability that is not an address space",
        k::vspace_map(slot::CONSOLE, slot::SHARED_FRAME, VA_SHARED, Rights::READ),
        Error::WrongType,
    );
    a.expect(
        "unmap a frame that is not mapped",
        // SAFETY: nothing is mapped through this capability yet.
        unsafe { k::vspace_unmap(slot::SHARED_FRAME) },
        Error::InvalidState,
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
        "map the same capability a second time",
        k::vspace_map(slot::VSPACE, slot::SHARED_FRAME, VA_SHARED_X, Rights::READ),
        Error::AlreadyMapped,
    );
    // A second (derived) capability to the frame cannot replace existing pages.
    let derived = k::cap_mint(slot::SHARED_FRAME, SCRATCH, Rights::READ, 0).is_ok();
    let code_page = (run as *const () as u64) & !0xfff;
    let local = 0u8;
    let stack_page = (&raw const local as u64) & !0xfff;
    a.expect(
        "replace its own code with the shared frame",
        k::vspace_map(slot::VSPACE, SCRATCH, code_page, Rights::READ),
        Error::AlreadyMapped,
    );
    a.expect(
        "replace its own stack with the shared frame",
        k::vspace_map(slot::VSPACE, SCRATCH, stack_page, Rights::READ),
        Error::AlreadyMapped,
    );
    a.report_allowed(
        "derive a read-only copy of its frame capability",
        derived,
        "minted",
    );
    let _ = k::cap_delete(SCRATCH);
}

/// User pointers handed to the kernel.
fn user_pointers(a: &mut Attacker) {
    for (what, ptr, len) in [
        ("a kernel image address", KERNEL_IMAGE, 64),
        ("the kernel's direct map", 0xffff_8000_0000_0000, 64),
        ("a non-canonical address", 0x0000_8000_0000_0000, 8),
        ("the null page", 0, 8),
        ("a pointer whose end wraps around", u64::MAX - 3, 16),
        (
            "a buffer straddling the end of user space",
            abi::USER_TOP - 4,
            16,
        ),
        ("an unmapped user address", 0x0000_6000_0000_0000, 8),
        (
            "a buffer running off the end of a mapped page",
            VA_SHARED + 4096 - 16,
            17,
        ),
        (
            "a buffer starting just before a mapped page",
            VA_SHARED - 1,
            8,
        ),
    ] {
        let blocked = write_raw(ptr, len) == Err(Error::BadAddress);
        a.report("make the kernel read memory for us", blocked, what);
    }
    a.expect(
        "pass an oversized buffer",
        write_raw(VA_SHARED, 4097),
        Error::InvalidArgument,
    );
    // The last 16 bytes of the shared page are readable right up to the boundary.
    let ok = write_raw(VA_SHARED + 4096 - 16, 16).is_ok();
    a.report_allowed(
        "print a buffer that ends exactly at a page boundary",
        ok,
        "accepted",
    );
}

/// Kernel memory exhaustion.
fn exhaustion(a: &mut Attacker) {
    // SAFETY: nothing references the shared page any more.
    let _ = unsafe { k::vspace_unmap(slot::SHARED_FRAME) };
    let _ = k::call(slot::ENDPOINT, [selftest::MARK, 1, 0, 0], None);

    // Map and unmap a frame at 2000 fresh addresses (each needs new page tables).
    // Empty tables must be reclaimed, so this costs the kernel nothing.
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
        "page tables reclaimed",
    );
    let _ = k::call(slot::ENDPOINT, [selftest::MARK, 2, 0, 0], None);

    // Keep many sparse mappings alive at once: the page-table quota must stop it.
    let mut mapped = 0;
    let mut last = Ok(());
    for i in 0..200u64 {
        let s = SCRATCH + i;
        last = k::cap_mint(slot::SHARED_FRAME, s, Rights::READ, 0)
            .and_then(|()| k::vspace_map(slot::VSPACE, s, (i + 1) << 39, Rights::READ));
        if last.is_err() {
            break;
        }
        mapped += 1;
    }
    a.report(
        "exhaust kernel memory with sparse mappings",
        last == Err(Error::OutOfMemory) && mapped < 64,
        "stopped by the page-table quota",
    );
    // Dropping the capabilities removes the mappings and returns every table.
    let _ = k::cap_revoke(slot::SHARED_FRAME);
    let _ = k::call(slot::ENDPOINT, [selftest::MARK, 3, 0, 0], None);
    let remap = k::vspace_map(slot::VSPACE, slot::SHARED_FRAME, VA_SHARED, Rights::READ).is_ok();
    a.report_allowed("map again after hitting the quota", remap, "quota released");
}

pub fn run() -> ! {
    println!(
        "sandbox started at {:#x} with 4 capabilities; attempting to escape...",
        run as *const () as usize
    );
    let mut a = Attacker { id: 0 };
    ambient_authority(&mut a);
    escalation(&mut a);
    ipc_abuse(&mut a);
    capability_table(&mut a);
    memory(&mut a);
    exhaustion(&mut a);
    user_pointers(&mut a);
    println!(
        "  [INFO] terminal escape injection attempt follows: \x1b[2J\x1b[31mFAKE KERNEL LOG\x1b[0m"
    );

    let _ = k::call(slot::ENDPOINT, [selftest::DONE, a.id, 0, 0], None);

    // Finally, read kernel memory directly. The MMU must stop this (supervisor
    // page) and the kernel must kill us and notify our supervisor.
    println!("  reading kernel memory at {KERNEL_IMAGE:#x} ...");
    // SAFETY: this is the attack — it is *expected* to fault.
    let leaked = unsafe { core::ptr::read_volatile(KERNEL_IMAGE as *const u64) };
    println!("  [ESCAPED] read kernel memory: {leaked:#x}");
    k::thread_exit(selftest::EXIT_ESCAPED)
}
