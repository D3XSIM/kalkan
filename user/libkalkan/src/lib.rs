//! # libkalkan
//!
//! Thin, typed wrappers around the Kalkan system call interface.
//!
//! Every kernel object is named by a capability *slot* in the calling thread's
//! capability space. The kernel validates every argument; nothing here is trusted.

#![no_std]

use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};

pub use kcore::abi::{self, Error};
pub use kcore::rights::Rights;

/// Result of a system call.
pub type Result<T> = core::result::Result<T, Error>;

/// Raw register state returned by a system call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Regs {
    /// Status (0 or an [`Error`] code).
    pub rax: u64,
    /// Return value 0.
    pub rdi: u64,
    /// Return value 1.
    pub rsi: u64,
    /// Return value 2.
    pub rdx: u64,
    /// Return value 3.
    pub r10: u64,
    /// Return value 4.
    pub r8: u64,
    /// Return value 5.
    pub r9: u64,
}

impl Regs {
    /// Converts the status register into a `Result`.
    pub fn status(&self) -> Result<()> {
        status(self.rax)
    }
}

fn status(rax: u64) -> Result<()> {
    if rax == 0 {
        Ok(())
    } else {
        Err(Error::from_raw(rax).unwrap_or(Error::InvalidArgument))
    }
}

/// Issues a raw system call.
///
/// # Safety
///
/// The kernel validates every argument, so this cannot compromise the kernel or
/// other processes. It can, however, break the *calling* program's own memory
/// safety (for example by unmapping memory that Rust code is still using).
#[inline(always)]
pub unsafe fn syscall(n: u64, a: [u64; 6]) -> Regs {
    let (rax, rdi, rsi, rdx, r10, r8, r9);
    // SAFETY: `syscall` only clobbers rcx/r11 (declared) and the argument registers
    // (declared as in/out). The kernel preserves every other register.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") n => rax,
            inlateout("rdi") a[0] => rdi,
            inlateout("rsi") a[1] => rsi,
            inlateout("rdx") a[2] => rdx,
            inlateout("r10") a[3] => r10,
            inlateout("r8") a[4] => r8,
            inlateout("r9") a[5] => r9,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    Regs {
        rax,
        rdi,
        rsi,
        rdx,
        r10,
        r8,
        r9,
    }
}

#[inline(always)]
fn sys(n: u64, a: [u64; 6]) -> Regs {
    // SAFETY: the wrappers below only issue system calls that cannot invalidate
    // memory used by Rust code (unmapping goes through `vspace_unmap`, which is
    // itself `unsafe`).
    unsafe { syscall(n, a) }
}

/// Writes text to the kernel debug console (requires `WRITE` on the console cap).
pub fn debug_write(console: u64, text: &str) -> Result<()> {
    let r = sys(
        abi::sys::DEBUG_WRITE,
        [console, text.as_ptr() as u64, text.len() as u64, 0, 0, 0],
    );
    r.status()
}

/// Derives a copy of `src` into `dst` with (a subset of) its rights and an optional badge.
pub fn cap_mint(src: u64, dst: u64, rights: Rights, badge: u64) -> Result<()> {
    sys(abi::sys::CAP_MINT, [src, dst, rights.bits(), badge, 0, 0]).status()
}

/// Copies a capability with identical rights.
pub fn cap_copy(src: u64, dst: u64) -> Result<()> {
    let info = cap_info(src)?;
    cap_mint(src, dst, info.rights, 0)
}

/// Deletes a capability.
pub fn cap_delete(slot: u64) -> Result<()> {
    sys(abi::sys::CAP_DELETE, [slot, 0, 0, 0, 0, 0]).status()
}

/// Deletes every capability derived from `slot`.
pub fn cap_revoke(slot: u64) -> Result<()> {
    sys(abi::sys::CAP_REVOKE, [slot, 0, 0, 0, 0, 0]).status()
}

/// Information about a capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapInfo {
    /// Object type (see [`abi::obj`]).
    pub obj_type: u64,
    /// Rights.
    pub rights: Rights,
    /// Badge.
    pub badge: u64,
}

/// Inspects a capability.
pub fn cap_info(slot: u64) -> Result<CapInfo> {
    let r = sys(abi::sys::CAP_INFO, [slot, 0, 0, 0, 0, 0]);
    r.status()?;
    Ok(CapInfo {
        obj_type: r.rdi,
        rights: Rights::from_bits(r.rsi).unwrap_or_default(),
        badge: r.rdx,
    })
}

/// Creates a new kernel object of `obj_type` from an untyped budget.
pub fn retype(untyped: u64, obj_type: u64, dst: u64) -> Result<()> {
    sys(abi::sys::UNTYPED_RETYPE, [untyped, obj_type, dst, 0, 0, 0]).status()
}

/// Maps a frame at `vaddr` with `perms` (READ / WRITE / EXEC; never WRITE + EXEC).
pub fn vspace_map(vspace: u64, frame: u64, vaddr: u64, perms: Rights) -> Result<()> {
    sys(
        abi::sys::VSPACE_MAP,
        [vspace, frame, vaddr, perms.bits(), 0, 0],
    )
    .status()
}

/// Unmaps a frame.
///
/// # Safety
///
/// No Rust reference may point into the unmapped page afterwards.
pub unsafe fn vspace_unmap(frame: u64) -> Result<()> {
    sys(abi::sys::VSPACE_UNMAP, [frame, 0, 0, 0, 0, 0]).status()
}

/// Mints `src` into slot `dst` of another thread's capability space.
pub fn thread_grant(thread: u64, src: u64, dst: u64, rights: Rights, badge: u64) -> Result<()> {
    sys(
        abi::sys::THREAD_GRANT,
        [thread, src, dst, rights.bits(), badge, 0],
    )
    .status()
}

/// Starts an inactive thread.
pub fn thread_start(thread: u64) -> Result<()> {
    sys(abi::sys::THREAD_START, [thread, 0, 0, 0, 0, 0]).status()
}

/// Routes the faults of `thread` to `endpoint` (the badge of the endpoint cap is
/// delivered with every fault message).
pub fn thread_set_fault_ep(thread: u64, endpoint: u64) -> Result<()> {
    sys(
        abi::sys::THREAD_SET_FAULT_EP,
        [thread, endpoint, 0, 0, 0, 0],
    )
    .status()
}

/// Terminates the calling thread.
pub fn thread_exit(code: u64) -> ! {
    sys(abi::sys::THREAD_EXIT, [code, 0, 0, 0, 0, 0]);
    // The kernel never returns from a successful exit; spin defensively.
    loop {
        core::hint::spin_loop();
    }
}

/// Gives up the remaining time slice.
pub fn yield_now() {
    sys(abi::sys::YIELD, [0; 6]);
}

/// Returns 64 bits from the kernel CSPRNG.
pub fn random() -> u64 {
    sys(abi::sys::RANDOM, [0; 6]).rdi
}

/// Aggregate kernel resource usage (see [`kernel_stats`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KernelStats {
    /// Free physical frames.
    pub free_frames: u64,
    /// Bytes allocated on the kernel heap.
    pub heap_bytes: u64,
    /// Live capabilities in all capability spaces.
    pub capabilities: u64,
    /// Live threads.
    pub threads: u64,
    /// Live frame objects.
    pub frames: u64,
    /// Live endpoints.
    pub endpoints: u64,
}

/// Reads the kernel's resource statistics (requires `READ` on the console cap).
pub fn kernel_stats(console: u64) -> Result<KernelStats> {
    let r = sys(abi::sys::KERNEL_STATS, [console, 0, 0, 0, 0, 0]);
    r.status()?;
    Ok(KernelStats {
        free_frames: r.rdi,
        heap_bytes: r.rsi,
        capabilities: r.rdx,
        threads: r.r10,
        frames: r.r8,
        endpoints: r.r9,
    })
}

fn cap_arg(cap: Option<u64>) -> u64 {
    cap.unwrap_or(abi::NO_CAP)
}

/// Blocking send of four message words and optionally one capability.
pub fn send(ep: u64, msg: [u64; 4], cap: Option<u64>) -> Result<()> {
    sys(
        abi::sys::EP_SEND,
        [ep, msg[0], msg[1], msg[2], msg[3], cap_arg(cap)],
    )
    .status()
}

/// A received message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Message {
    /// Badge of the capability the sender used.
    pub badge: u64,
    /// Message words.
    pub words: [u64; 4],
    /// Flags (see [`abi::msg`]).
    pub info: u64,
}

impl Message {
    /// `true` if this is a kernel-generated fault report.
    #[must_use]
    pub const fn is_fault(&self) -> bool {
        self.info & abi::msg::FAULT != 0
    }
}

/// Blocking receive. A transferred capability (if any) lands in `recv_slot`.
pub fn recv(ep: u64, recv_slot: Option<u64>) -> Result<Message> {
    let r = sys(abi::sys::EP_RECV, [ep, cap_arg(recv_slot), 0, 0, 0, 0]);
    r.status()?;
    Ok(Message {
        badge: r.rdi,
        words: [r.rsi, r.rdx, r.r10, r.r8],
        info: r.r9,
    })
}

/// Sends a message and blocks until the receiver replies.
pub fn call(ep: u64, msg: [u64; 4], cap: Option<u64>) -> Result<[u64; 4]> {
    let r = sys(
        abi::sys::EP_CALL,
        [ep, msg[0], msg[1], msg[2], msg[3], cap_arg(cap)],
    );
    r.status()?;
    Ok([r.rsi, r.rdx, r.r10, r.r8])
}

/// Replies to the thread whose call was received last (one-shot).
pub fn reply(msg: [u64; 4]) -> Result<()> {
    sys(abi::sys::EP_REPLY, [msg[0], msg[1], msg[2], msg[3], 0, 0]).status()
}

pub mod selftest;

static CONSOLE: AtomicU64 = AtomicU64::new(abi::slot::NULL);

/// Selects the console capability used by [`print!`] / [`println!`] and panics.
pub fn set_console(slot: u64) {
    CONSOLE.store(slot, Ordering::Relaxed);
}

/// Formatting sink that writes to the console capability.
#[derive(Debug)]
pub struct Console;

impl fmt::Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        debug_write(CONSOLE.load(Ordering::Relaxed), s).map_err(|_| fmt::Error)
    }
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments<'_>) {
    // Format into a small stack buffer so each line is one system call.
    struct Buf {
        data: [u8; 256],
        len: usize,
    }
    impl fmt::Write for Buf {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            for &b in s.as_bytes() {
                if self.len == self.data.len() {
                    flush(self);
                }
                self.data[self.len] = b;
                self.len += 1;
            }
            Ok(())
        }
    }
    fn flush(b: &mut Buf) {
        if let Ok(s) = core::str::from_utf8(&b.data[..b.len]) {
            let _ = debug_write(CONSOLE.load(Ordering::Relaxed), s);
        }
        b.len = 0;
    }
    let mut buf = Buf {
        data: [0; 256],
        len: 0,
    };
    let _ = fmt::write(&mut buf, args);
    flush(&mut buf);
}

/// Prints to the console capability selected with [`set_console`].
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => { $crate::_print(format_args!($($arg)*)) };
}

/// Prints a line to the console capability selected with [`set_console`].
#[macro_export]
macro_rules! println {
    () => { $crate::print!("\n") };
    ($($arg:tt)*) => { $crate::_print(format_args!("{}\n", format_args!($($arg)*))) };
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    println!("user panic: {}", info.message());
    thread_exit(0xdead);
}
