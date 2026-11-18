//! Kernel entry and exit paths: interrupts, exceptions and system calls.
//!
//! Kalkan uses a **single kernel stack** and an event-driven design (like seL4):
//! every entry from user mode pushes a [`TrapFrame`] at the top of the kernel
//! stack, the kernel handles the event to completion — it never blocks or sleeps
//! in kernel mode — and then returns to whichever thread the scheduler picked by
//! overwriting the frame with that thread's saved registers. There are no kernel
//! threads and no kernel-stack switching, which removes a whole class of
//! concurrency bugs.
//!
//! Hardening on every entry:
//! * `swapgs` only when coming from user mode, followed by `lfence` (SWAPGS
//!   speculation, CVE-2019-1125);
//! * `clac`, so SMAP is enforced even if user space set `RFLAGS.AC`;
//! * `cld`, and **every general purpose register is zeroed** before calling into
//!   Rust, so stale user values cannot be used as speculative gadget inputs.
//!
//! The kernel always returns with `iretq` (never `sysretq`), which side-steps the
//! SYSRET non-canonical return address privilege escalation class
//! (CVE-2012-0217).

use core::arch::{asm, global_asm};
use core::mem::size_of;

use super::gdt::{USER_CS, USER_DS};

/// Pseudo vector number used for system calls.
pub const SYSCALL_VECTOR: u64 = 0x100;
/// Vector of the local APIC timer.
pub const TIMER_VECTOR: u64 = 32;
/// Vector of spurious local APIC interrupts.
pub const SPURIOUS_VECTOR: u64 = 0xff;

/// Register state saved on kernel entry (layout shared with the assembly below).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct TrapFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    pub vector: u64,
    pub error_code: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

const _: () = assert!(size_of::<TrapFrame>() == 22 * 8);
const _: () = assert!(size_of::<TrapFrame>().is_multiple_of(16));

/// User-controllable RFLAGS bits: CF, PF, AF, ZF, SF, DF, OF.
/// IOPL, NT, AC, TF, RF, VM etc. are always cleared; IF is always set.
const USER_RFLAGS_MASK: u64 = 0x0cd5;

impl TrapFrame {
    /// Initial register state for a new user thread.
    #[must_use]
    pub fn new_user(entry: u64, stack_top: u64, arg: u64) -> Self {
        Self {
            rip: entry,
            rsp: stack_top,
            rdi: arg,
            cs: u64::from(USER_CS),
            ss: u64::from(USER_DS),
            rflags: 0x202,
            ..Self::default()
        }
    }

    /// `true` if the frame was pushed by an entry from user mode.
    #[must_use]
    pub const fn is_user_mode(&self) -> bool {
        self.cs & 3 == 3
    }

    /// Forces the privilege-relevant fields to safe user-mode values. Called on
    /// every return to user space, so a corrupted saved context can never return
    /// to ring 0 or with interrupts disabled.
    pub fn sanitize_for_user(&mut self) {
        self.cs = u64::from(USER_CS);
        self.ss = u64::from(USER_DS);
        self.rflags = (self.rflags & USER_RFLAGS_MASK) | 0x202;
    }
}

global_asm!(
    r#"
    .section .text.kalkan_entry, "ax"

    .p2align 4
    .global kalkan_isr_stubs
kalkan_isr_stubs:
    .set kalkan_vec, 0
    .rept 256
        .p2align 4
        .if (kalkan_vec == 8) || (kalkan_vec == 10) || (kalkan_vec == 11) || (kalkan_vec == 12) || (kalkan_vec == 13) || (kalkan_vec == 14) || (kalkan_vec == 17) || (kalkan_vec == 21) || (kalkan_vec == 29) || (kalkan_vec == 30)
            pushq $kalkan_vec
        .else
            pushq $0
            pushq $kalkan_vec
        .endif
        jmp kalkan_isr_common
        .set kalkan_vec, kalkan_vec + 1
    .endr

    .p2align 4
kalkan_isr_common:
    /* [rsp] vector, [rsp+8] error, [rsp+16] rip, [rsp+24] cs */
    testb $3, 24(%rsp)
    jz 1f
    swapgs
1:
    lfence
    clac
    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdx
    pushq %rsi
    pushq %rdi
    pushq %rbp
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    jmp kalkan_trap_common

    .p2align 4
    .global kalkan_syscall_entry
kalkan_syscall_entry:
    swapgs
    movq %rsp, %gs:8
    movq %gs:0, %rsp
    pushq ${user_ds}
    pushq %gs:8
    pushq %r11
    pushq ${user_cs}
    pushq %rcx
    pushq $0
    pushq ${syscall_vector}
    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdx
    pushq %rsi
    pushq %rdi
    pushq %rbp
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    lfence

kalkan_trap_common:
    cld
    movq %rsp, %rdi
    xorl %eax, %eax
    xorl %ebx, %ebx
    xorl %ecx, %ecx
    xorl %edx, %edx
    xorl %esi, %esi
    xorl %ebp, %ebp
    xorl %r8d, %r8d
    xorl %r9d, %r9d
    xorl %r10d, %r10d
    xorl %r11d, %r11d
    xorl %r12d, %r12d
    xorl %r13d, %r13d
    xorl %r14d, %r14d
    xorl %r15d, %r15d
    call kalkan_trap_entry

    .global kalkan_trap_return
kalkan_trap_return:
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rbp
    popq %rdi
    popq %rsi
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax
    addq $16, %rsp
    testb $3, 8(%rsp)
    jz 2f
    swapgs
2:
    iretq
    "#,
    user_ds = const USER_DS,
    user_cs = const USER_CS,
    syscall_vector = const SYSCALL_VECTOR,
    options(att_syntax)
);

unsafe extern "C" {
    static kalkan_trap_return: u8;
}

/// Address of the `syscall` entry point (for `IA32_LSTAR`).
#[must_use]
pub fn syscall_entry_address() -> u64 {
    unsafe extern "C" {
        static kalkan_syscall_entry: u8;
    }
    &raw const kalkan_syscall_entry as u64
}

/// Called by the assembly stubs for every interrupt, exception and system call.
#[unsafe(no_mangle)]
extern "C" fn kalkan_trap_entry(frame: *mut TrapFrame) {
    // SAFETY: the stub passes a pointer to the frame it just pushed; it is valid,
    // aligned and not aliased for the duration of this call.
    let frame = unsafe { &mut *frame };
    if frame.is_user_mode() {
        crate::kernel::user_trap(frame);
        frame.sanitize_for_user();
        super::cpu::clear_cpu_buffers();
    } else {
        kernel_trap(frame);
    }
}

/// A trap taken while executing kernel code.
///
/// The kernel runs with interrupts disabled, so the only possible causes are CPU
/// exceptions — i.e. kernel bugs — or NMI / machine check. All of them are fatal:
/// the kernel stops instead of continuing in a possibly corrupted state.
fn kernel_trap(frame: &TrapFrame) {
    match frame.vector {
        SPURIOUS_VECTOR => {}
        8 => panic!("double fault (kernel stack overflow into a guard page?)\n{frame:#x?}"),
        14 => panic!(
            "kernel page fault at {:#x} (error {:#x}, rip {:#x})",
            super::read_cr2(),
            frame.error_code,
            frame.rip
        ),
        v => panic!(
            "unexpected kernel trap: vector {v}, error {:#x}, rip {:#x}, rsp {:#x}",
            frame.error_code, frame.rip, frame.rsp
        ),
    }
}

/// Enters user mode for the first time with the given register state.
///
/// The frame is placed at the very top of the kernel stack (where the CPU would
/// have put it on a real entry) and the common return path restores it. Every
/// kernel stack frame below is discarded: the kernel never returns here.
pub fn enter_user(frame: &TrapFrame, kernel_stack_top: u64) -> ! {
    let mut frame = *frame;
    frame.sanitize_for_user();
    let dst = (kernel_stack_top - size_of::<TrapFrame>() as u64) as *mut TrapFrame;
    let trap_return = &raw const kalkan_trap_return as u64;
    // SAFETY: `dst` lies inside the current, mapped kernel stack. `ptr::copy` has
    // memmove semantics, so overlap with the source is fine. After the copy we
    // switch to the frame and jump to the return path, never touching the old
    // stack frames again.
    unsafe {
        core::ptr::copy(&raw const frame, dst, 1);
        asm!(
            "mov rsp, {frame}",
            "jmp {ret}",
            frame = in(reg) dst,
            ret = in(reg) trap_return,
            options(noreturn),
        );
    }
}

/// Activates the kernel's own page tables and continues on its guard-paged stack.
///
/// Both switches happen in one instruction sequence, so no code ever runs with the
/// bootloader's stack under the kernel's page tables.
///
/// # Safety
///
/// `pml4` must map the kernel image, the direct map and `stack_top`; `next` must
/// never return.
pub unsafe fn switch_to_kernel_space(pml4: u64, stack_top: u64, next: extern "C" fn() -> !) -> ! {
    // SAFETY: guaranteed by the caller.
    unsafe {
        asm!(
            "mov cr3, {pml4}",
            "mov rsp, {top}",
            "xor ebp, ebp",
            "call {next}",
            "ud2",
            pml4 = in(reg) pml4,
            top = in(reg) stack_top,
            next = in(reg) next,
            options(noreturn),
        );
    }
}
