//! The user/kernel ABI.
//!
//! This module is shared verbatim between the kernel and user space so that both
//! sides agree on system call numbers, error codes and the initial capability
//! layout.
//!
//! ## Calling convention
//!
//! System calls use the `syscall` instruction:
//!
//! | Register | In                    | Out                         |
//! |----------|-----------------------|-----------------------------|
//! | `rax`    | system call number    | status ([`Error`] or 0)     |
//! | `rdi`    | argument 0            | return value 0 (e.g. badge) |
//! | `rsi`    | argument 1            | return value 1              |
//! | `rdx`    | argument 2            | return value 2              |
//! | `r10`    | argument 3            | return value 3              |
//! | `r8`     | argument 4            | return value 4              |
//! | `r9`     | argument 5            | return value 5              |
//!
//! `rcx` and `r11` are clobbered by the CPU. All other registers are preserved.

/// System call numbers.
pub mod sys {
    /// `debug_write(console, ptr, len)` — write UTF-8 text to the kernel console.
    pub const DEBUG_WRITE: u64 = 0;
    /// `cap_mint(src, dst, rights, badge)` — derive a (weaker) copy of a capability.
    pub const CAP_MINT: u64 = 1;
    /// `cap_delete(slot)` — delete a capability.
    pub const CAP_DELETE: u64 = 2;
    /// `cap_revoke(slot)` — delete every capability derived from `slot`.
    pub const CAP_REVOKE: u64 = 3;
    /// `cap_info(slot) -> (type, rights, badge)`.
    pub const CAP_INFO: u64 = 4;
    /// `untyped_retype(untyped, obj_type, dst)` — create a new kernel object.
    pub const UNTYPED_RETYPE: u64 = 5;
    /// `vspace_map(vspace, frame, vaddr, perms)` — map a frame into an address space.
    pub const VSPACE_MAP: u64 = 6;
    /// `vspace_unmap(frame)` — unmap a previously mapped frame.
    pub const VSPACE_UNMAP: u64 = 7;
    /// `thread_grant(thread, src, dst, rights, badge)` — mint a capability into
    /// another thread's capability space.
    pub const THREAD_GRANT: u64 = 8;
    /// `thread_start(thread)` — make an inactive thread runnable.
    pub const THREAD_START: u64 = 9;
    /// `thread_set_fault_ep(thread, endpoint)` — route faults to an endpoint.
    pub const THREAD_SET_FAULT_EP: u64 = 10;
    /// `thread_exit(code)` — terminate the calling thread.
    pub const THREAD_EXIT: u64 = 11;
    /// `yield()` — give up the rest of the time slice.
    pub const YIELD: u64 = 12;
    /// `ep_send(ep, m0, m1, m2, m3, cap)` — blocking send.
    pub const EP_SEND: u64 = 13;
    /// `ep_recv(ep, recv_slot) -> (badge, m0, m1, m2, m3, info)` — blocking receive.
    pub const EP_RECV: u64 = 14;
    /// `ep_call(ep, m0, m1, m2, m3, cap) -> (_, m0, m1, m2, m3)` — send and wait for reply.
    pub const EP_CALL: u64 = 15;
    /// `ep_reply(m0, m1, m2, m3)` — reply to the last caller (one-shot).
    pub const EP_REPLY: u64 = 16;
    /// `random(entropy) -> value` — 64 bits from the kernel CSPRNG. Requires `READ`
    /// on an entropy capability: like everything else, randomness is not ambient.
    pub const RANDOM: u64 = 17;
    /// `thread_kill(thread)` — terminate another thread (or the caller itself) and
    /// release everything it owns. Requires `WRITE` on the thread capability.
    pub const THREAD_KILL: u64 = 18;
    /// `kernel_stats(console) -> (free frames, heap bytes, capabilities, threads,
    /// frame objects, endpoints)` — aggregate kernel resource usage. Requires `READ`
    /// on a console capability. **Test kernels only** (`selftest` feature); other
    /// kernels return [`super::Error::NoSys`].
    pub const KERNEL_STATS: u64 = 19;
    /// `kernel_layout(console) -> (text, data, direct map, stack, heap)` — addresses
    /// of live kernel memory, so the test suite can aim its attacks at the real
    /// kernel despite KASLR. Requires `READ` on a console capability. **Test kernels
    /// only**; other kernels return [`super::Error::NoSys`].
    pub const KERNEL_LAYOUT: u64 = 20;
    /// Number of system calls. Any number `>= COUNT` returns [`super::Error::NoSys`].
    pub const COUNT: u64 = 21;
}

/// Error codes returned in `rax`. `0` means success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum Error {
    /// An argument was malformed (misaligned address, unknown flag bits, ...).
    InvalidArgument = 1,
    /// The capability does not carry the rights required by the operation.
    PermissionDenied = 2,
    /// The capability slot index is outside the capability space.
    BadSlot = 3,
    /// The capability slot is empty.
    EmptySlot = 4,
    /// The destination slot is already occupied.
    SlotOccupied = 5,
    /// The capability refers to an object of the wrong type.
    WrongType = 6,
    /// A memory budget or kernel limit was exhausted.
    OutOfMemory = 7,
    /// A user pointer was invalid (kernel address, overflow, unmapped).
    BadAddress = 8,
    /// Unknown system call.
    NoSys = 9,
    /// The object is not in a state that allows the operation.
    InvalidState = 10,
    /// The peer object was destroyed while the operation was pending.
    Dead = 11,
    /// The address is already mapped.
    AlreadyMapped = 12,
    /// A W+X mapping or another W^X violation was requested.
    WxViolation = 13,
}

impl Error {
    /// Converts a raw status value back into an [`Error`].
    #[must_use]
    pub const fn from_raw(raw: u64) -> Option<Self> {
        Some(match raw {
            1 => Self::InvalidArgument,
            2 => Self::PermissionDenied,
            3 => Self::BadSlot,
            4 => Self::EmptySlot,
            5 => Self::SlotOccupied,
            6 => Self::WrongType,
            7 => Self::OutOfMemory,
            8 => Self::BadAddress,
            9 => Self::NoSys,
            10 => Self::InvalidState,
            11 => Self::Dead,
            12 => Self::AlreadyMapped,
            13 => Self::WxViolation,
            _ => return None,
        })
    }

    /// Short human readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidArgument => "EINVAL",
            Self::PermissionDenied => "EPERM",
            Self::BadSlot => "EBADSLOT",
            Self::EmptySlot => "EEMPTY",
            Self::SlotOccupied => "EEXIST",
            Self::WrongType => "ETYPE",
            Self::OutOfMemory => "ENOMEM",
            Self::BadAddress => "EFAULT",
            Self::NoSys => "ENOSYS",
            Self::InvalidState => "ESTATE",
            Self::Dead => "EDEAD",
            Self::AlreadyMapped => "EMAPPED",
            Self::WxViolation => "EWX",
        }
    }
}

/// Object types for `untyped_retype` and `cap_info`.
pub mod obj {
    /// An untyped memory budget.
    pub const UNTYPED: u64 = 1;
    /// One 4 KiB physical page frame.
    pub const FRAME: u64 = 2;
    /// An address space.
    pub const VSPACE: u64 = 3;
    /// A thread.
    pub const THREAD: u64 = 4;
    /// An IPC endpoint.
    pub const ENDPOINT: u64 = 5;
    /// The kernel debug console.
    pub const CONSOLE: u64 = 6;
    /// The kernel's random number generator.
    pub const ENTROPY: u64 = 7;
}

/// Kernel-charged cost (in bytes of the untyped budget) of each retypable object.
pub mod cost {
    /// A frame costs exactly its size.
    pub const FRAME: u64 = 4096;
    /// Endpoints are small kernel objects.
    pub const ENDPOINT: u64 = 256;
}

/// Well-known capability slots in the initial capability space of the root task.
pub mod slot {
    /// Slot 0 is the null slot: it is always empty and is rejected as a
    /// destination, so a zeroed argument can never name a capability.
    pub const NULL: u64 = 0;
    /// The root task's own address space.
    pub const SELF_VSPACE: u64 = 1;
    /// The root task's own thread.
    pub const SELF_THREAD: u64 = 2;
    /// An untyped memory budget.
    pub const UNTYPED: u64 = 3;
    /// The kernel debug console (`READ | WRITE | GRANT`).
    pub const CONSOLE: u64 = 4;
    /// The (not yet started) sandbox thread.
    pub const SANDBOX_THREAD: u64 = 5;
    /// The sandbox's address space.
    pub const SANDBOX_VSPACE: u64 = 6;
    /// The kernel's random number generator (`READ | GRANT`).
    pub const ENTROPY: u64 = 7;
    /// First slot that is free for the root task to use.
    pub const FIRST_FREE: u64 = 8;
    /// Thread capabilities of the probe processes (`PROBE_COUNT` slots).
    pub const PROBE_THREAD_FIRST: u64 = 64;
    /// Address space capabilities of the probe processes (`PROBE_COUNT` slots).
    pub const PROBE_VSPACE_FIRST: u64 = 128;
}

/// Number of *probe* processes a test kernel (`selftest` feature) creates at boot
/// besides the sandbox: extra, never-started instances of the sandbox image. The
/// self-test suite starts each one to perform a single attack that is expected to
/// get it killed. Other kernels create none.
pub const PROBE_COUNT: u64 = 60;

/// Number of slots in every capability space.
pub const CSPACE_SLOTS: usize = 256;

/// Value meaning "no capability" in cap-transfer arguments.
pub const NO_CAP: u64 = u64::MAX;

/// Flags returned in `r9` by `ep_recv`.
pub mod msg {
    /// A capability was transferred into the receive slot.
    pub const CAP_TRANSFERRED: u64 = 1 << 0;
    /// The sender tried to transfer a capability but the transfer was refused.
    pub const CAP_REFUSED: u64 = 1 << 1;
    /// This message is a report about a supervised thread generated by the kernel
    /// (a fault, or a voluntary exit — see [`super::EXIT_VECTOR`]).
    pub const FAULT: u64 = 1 << 2;
}

/// Pseudo vector in `words[0]` of a fault message reporting a voluntary exit
/// (`words[1]` holds the exit code).
pub const EXIT_VECTOR: u64 = 0x100;

/// Size of the user portion of every address space: `[0, USER_TOP)`.
///
/// The last 64 KiB below the canonical hole are deliberately left unusable so that
/// no user mapping can ever be adjacent to a non-canonical address.
pub const USER_TOP: u64 = 0x0000_7fff_ffff_0000;

/// Lowest address user mappings may use (the first 4 MiB are never mapped so that
/// null-pointer dereferences with offsets always fault).
pub const USER_BOTTOM: u64 = 0x0000_0000_0040_0000;

/// Page size.
pub const PAGE_SIZE: u64 = 4096;

/// Returns `true` if `[addr, addr + len)` lies entirely within user space.
#[must_use]
pub const fn is_user_range(addr: u64, len: u64) -> bool {
    match addr.checked_add(len) {
        Some(end) => addr >= USER_BOTTOM && end <= USER_TOP,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_roundtrip() {
        for raw in 1..=13 {
            let e = Error::from_raw(raw).expect("valid error code");
            assert_eq!(e as u64, raw);
        }
        assert_eq!(Error::from_raw(0), None);
        assert_eq!(Error::from_raw(14), None);
    }

    #[test]
    fn user_range() {
        assert!(is_user_range(USER_BOTTOM, PAGE_SIZE));
        assert!(!is_user_range(0, 1));
        assert!(!is_user_range(USER_TOP - 1, 2));
        assert!(!is_user_range(u64::MAX - 4, 16));
        assert!(!is_user_range(0xffff_8000_0000_0000, 8));
        assert!(is_user_range(USER_TOP - 8, 8));
    }
}
