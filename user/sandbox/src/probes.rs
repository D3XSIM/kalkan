//! Fault-containment probes.
//!
//! Each probe process performs exactly one of these actions. Almost all of them
//! are attacks on the hardware-enforced isolation boundary: the CPU must raise an
//! exception and the kernel must terminate *only this process* and report the
//! fault to its supervisor. If an attack returns normally, the probe exits with
//! [`selftest::EXIT_ESCAPED`].

use core::arch::asm;
use core::hint::black_box;
use core::ptr::{read_volatile, write_volatile};

use libkalkan::selftest::{self, mode};
use libkalkan::{self as k, abi, println};

const KERNEL_IMAGE: u64 = 0xffff_ffff_8000_0000;
const KERNEL_PHYSMAP: u64 = 0xffff_8000_0010_0000;
const NON_CANONICAL: u64 = 0x0000_8000_0000_0000;

/// Read-only data (lives in `.rodata`).
static READ_ONLY: [u8; 16] = *b"kalkan-read-only";
/// Writable data that happens to contain a `ret` instruction (lives in `.data`).
static mut WRITABLE_CODE: [u8; 16] = [0xc3; 16];

fn cpuid(leaf: u32, sub: u32) -> [u32; 4] {
    let (a, b, c, d): (u32, u64, u32, u32);
    // SAFETY: cpuid is unprivileged and has no side effects; rbx is preserved.
    unsafe {
        asm!(
            "mov {t}, rbx",
            "cpuid",
            "xchg {t}, rbx",
            t = out(reg) b,
            inout("eax") leaf => a,
            inout("ecx") sub => c,
            out("edx") d,
            options(nomem, nostack, preserves_flags),
        );
    }
    [a, b as u32, c, d]
}

fn has_umip() -> bool {
    cpuid(0, 0)[0] >= 7 && cpuid(7, 0)[2] & (1 << 2) != 0
}

#[inline(never)]
fn recurse(depth: u64) -> u64 {
    if black_box(depth) == u64::MAX {
        return 0;
    }
    let mut pad = [0u8; 1024];
    pad[(depth % 1024) as usize] = depth as u8;
    black_box(&mut pad);
    recurse(depth + 1) + u64::from(pad[0])
}

/// Calls `addr` as if it were a function.
///
/// # Safety
///
/// Never sound; only used where the call is expected to fault.
unsafe fn call(addr: u64) {
    // SAFETY: this is the attack — the call is expected to fault.
    let f: extern "C" fn() = unsafe { core::mem::transmute(addr as usize) };
    f();
}

/// Runs the probe for `mode`. Only returns if the attack was not stopped.
#[allow(clippy::too_many_lines)]
fn attack(mode: u64) -> Option<u64> {
    // SAFETY: (applies to the whole block) every statement below is a deliberate
    // attack on the isolation boundary. It is expected to raise a CPU exception,
    // after which the kernel terminates this process; none of them can affect
    // memory this program relies on if it unexpectedly succeeds.
    unsafe {
        match mode {
            mode::WRITE_KERNEL => write_volatile(KERNEL_IMAGE as *mut u64, 0x4141_4141_4141_4141),
            mode::READ_PHYSMAP => {
                black_box(read_volatile(KERNEL_PHYSMAP as *const u64));
            }
            mode::EXEC_KERNEL => call(KERNEL_IMAGE),
            mode::WRITE_CODE => write_volatile(attack as *const () as *mut u8, 0xc3),
            mode::WRITE_RODATA => write_volatile(black_box(READ_ONLY.as_ptr()).cast_mut(), 0),
            mode::EXEC_STACK => {
                let code = [0xc3u8; 16]; // ret
                call(black_box(code.as_ptr()) as u64);
            }
            mode::EXEC_DATA => call(black_box(&raw const WRITABLE_CODE) as u64),
            mode::NULL_DEREF => {
                black_box(read_volatile(black_box(8u64) as *const u64));
            }
            mode::STACK_OVERFLOW => {
                black_box(recurse(0));
            }
            mode::NONCANONICAL_READ => {
                black_box(read_volatile(NON_CANONICAL as *const u64));
            }
            mode::NONCANONICAL_JUMP => call(NON_CANONICAL),
            mode::HLT => asm!("hlt"),
            mode::CLI => asm!("cli"),
            mode::WRMSR => asm!("wrmsr", in("ecx") 0xc000_0082u32, in("eax") 0u32, in("edx") 0u32),
            mode::RDMSR => {
                let (lo, hi): (u32, u32);
                asm!("rdmsr", in("ecx") 0xc000_0082u32, out("eax") lo, out("edx") hi);
                println!("  LSTAR = {:#x}", (u64::from(hi) << 32) | u64::from(lo));
            }
            mode::READ_CR3 => {
                let cr3: u64;
                asm!("mov {}, cr3", out(reg) cr3);
                println!("  cr3 = {cr3:#x}");
            }
            mode::WRITE_CR4 => asm!("mov cr4, {}", in(reg) 0x20u64),
            mode::PORT_OUT => asm!("out dx, al", in("dx") 0x64u16, in("al") 0xfeu8),
            mode::PORT_IN => {
                let v: u8;
                asm!("in al, dx", in("dx") 0x60u16, out("al") v);
                black_box(v);
            }
            mode::LIDT => {
                let table = [0u8; 10];
                asm!("lidt [{}]", in(reg) table.as_ptr());
            }
            mode::LGDT => {
                let table = [0u8; 10];
                asm!("lgdt [{}]", in(reg) table.as_ptr());
            }
            mode::LTR => asm!("ltr {0:x}", in(reg) 0x28u64),
            mode::INT_0X80 => asm!("int 0x80"),
            mode::INT3 => asm!("int3"),
            mode::INT_TIMER => asm!("int 32"),
            mode::RDTSC => asm!("rdtsc", out("eax") _, out("edx") _),
            mode::RDPMC => asm!("rdpmc", in("ecx") 0u32, out("eax") _, out("edx") _),
            mode::SGDT | mode::SIDT => {
                let mut table = [0u8; 10];
                if mode == mode::SGDT {
                    asm!("sgdt [{}]", in(reg) table.as_mut_ptr());
                } else {
                    asm!("sidt [{}]", in(reg) table.as_mut_ptr());
                }
                if !has_umip() {
                    // Known limitation without UMIP: the instruction is not privileged.
                    return Some(selftest::EXIT_NOT_APPLICABLE);
                }
                let mut base = [0u8; 8];
                base.copy_from_slice(&table[2..]);
                println!("  descriptor table base = {:#x}", u64::from_le_bytes(base));
            }
            // The program is built without SSE/x87 support, so the instructions are
            // emitted as raw bytes.
            mode::SSE => asm!(".byte 0x0f, 0x57, 0xc0"), // xorps xmm0, xmm0
            mode::X87 => asm!(".byte 0xdb, 0xe3"),       // fninit
            mode::AVX => asm!(".byte 0xc5, 0xf8, 0x77"), // vzeroupper
            mode::XSETBV => {
                asm!(".byte 0x0f, 0x01, 0xd1", in("ecx") 0u32, in("eax") 7u32, in("edx") 0u32)
            }
            mode::WRGSBASE => asm!(".byte 0xf3, 0x48, 0x0f, 0xae, 0xd8", in("rax") KERNEL_IMAGE),
            mode::IRET_TO_RING0 => asm!(
                "mov {sp}, rsp",
                "push 0x10", // SS: kernel data
                "push {sp}",
                "push 0x2",
                "push 0x08", // CS: kernel code
                "lea {ip}, [rip + 2f]",
                "push {ip}",
                "iretq",
                "2:",
                sp = out(reg) _,
                ip = out(reg) _,
            ),
            mode::RETF_TO_RING0 => asm!(
                "push 0x08",
                "lea {ip}, [rip + 2f]",
                "push {ip}",
                "retfq",
                "2:",
                ip = out(reg) _,
            ),
            mode::LOAD_KERNEL_SS => asm!("mov ss, {0:x}", in(reg) 0x10u64),
            mode::SYSENTER => asm!("sysenter", out("rcx") _, out("rdx") _),
            mode::DIVIDE_BY_ZERO => asm!(
                "div {d}",
                d = in(reg) black_box(0u64),
                inout("rax") 1u64 => _,
                inout("rdx") 0u64 => _,
            ),
            mode::UD2 => asm!("ud2"),
            mode::SINGLE_STEP => asm!(
                "pushfq",
                "or qword ptr [rsp], 0x100", // TF
                "popfq",
                "nop",
                "nop",
            ),
            _ => return Some(selftest::EXIT_CHECK_FAILED),
        }
    }
    None
}

fn flags() -> u64 {
    let f: u64;
    // SAFETY: reads RFLAGS through the stack.
    unsafe { asm!("pushfq", "pop {}", out(reg) f, options(preserves_flags)) };
    f
}

/// Sets the trap flag and immediately enters the kernel. The kernel must neither
/// take a debug trap on its own entry path nor return the flag to user mode.
fn single_step_syscall() -> u64 {
    let status: u64;
    // SAFETY: `yield` has no effect on this program's memory; rcx/r11 are declared
    // as clobbered. If the trap flag survived, the process is killed by #DB, which
    // the supervisor reports.
    unsafe {
        asm!(
            "pushfq",
            "or qword ptr [rsp], 0x100",
            "popfq",
            "syscall",
            inlateout("rax") abi::sys::YIELD => status,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }
    if status != 0 {
        return selftest::EXIT_CHECK_FAILED | 1;
    }
    if flags() & 0x100 != 0 {
        return selftest::EXIT_CHECK_FAILED | 2;
    }
    selftest::EXIT_OK
}

/// Issues `yield` with `rsp` pointing at `evil` and with AC, NT and DF set.
/// Returns `(status, rflags after the call)`.
fn hostile_syscall(evil_rsp: u64) -> (u64, u64) {
    let (status, after): (u64, u64);
    // SAFETY: the real stack pointer is kept in r12, which the kernel preserves,
    // and is restored before any other code runs; DF is cleared again before
    // returning to Rust code. The kernel never uses the user stack pointer.
    unsafe {
        asm!(
            "pushfq",
            "or qword ptr [rsp], 0x44400", // AC | NT | DF
            "popfq",
            "mov r12, rsp",
            "mov rsp, {evil}",
            "syscall",
            "mov rsp, r12",
            "pushfq",
            "pop {after}",
            "cld",
            evil = in(reg) evil_rsp,
            after = lateout(reg) after,
            inlateout("rax") abi::sys::YIELD => status,
            lateout("rcx") _,
            lateout("r11") _,
            out("r12") _,
        );
    }
    (status, after)
}

fn hostile_stack_and_flags() -> u64 {
    let stacks = [
        0,
        8,
        KERNEL_IMAGE,
        KERNEL_PHYSMAP,
        NON_CANONICAL,
        0xdead_0000_0000,
        u64::MAX,
    ];
    for (i, &rsp) in stacks.iter().enumerate() {
        for _ in 0..50 {
            let (status, after) = hostile_syscall(rsp);
            if status != 0 {
                return selftest::EXIT_CHECK_FAILED | (0x10 + i as u64);
            }
            // The kernel must hand back neither AC (SMAP override) nor NT.
            if after & ((1 << 18) | (1 << 14)) != 0 {
                return selftest::EXIT_CHECK_FAILED | (0x20 + i as u64);
            }
            // Interrupts must be enabled and IOPL must be zero in user mode.
            if after & (1 << 9) == 0 || after & (3 << 12) != 0 {
                return selftest::EXIT_CHECK_FAILED | (0x30 + i as u64);
            }
        }
    }
    selftest::EXIT_OK
}

fn segment_registers() -> u64 {
    for selector in [0x1bu64, 0, 3, 0x1b] {
        // SAFETY: FS and GS are not used by this program; loading the user data
        // selector or a null selector into them is always permitted in ring 3.
        unsafe {
            asm!("mov fs, {0:x}", "mov gs, {0:x}", in(reg) selector);
        }
        for _ in 0..20 {
            k::yield_now();
            if k::cap_info(selftest::slot::ENDPOINT).is_err() {
                return selftest::EXIT_CHECK_FAILED | selector;
            }
        }
    }
    selftest::EXIT_OK
}

const PATTERN: u64 = 0x0000_1234_5678_0000;

/// Loads every general purpose register with a pattern, runs `body` (a system call
/// or a long busy loop), and returns the registers afterwards:
/// `[rax, rbx, rbp, rdi, rsi, rdx, r8, r9, r10, r11, r12, r13, r14, r15]`.
fn registers_after(nr: u64, spin: u64) -> [u64; 14] {
    let mut out = [0u64; 14];
    // SAFETY: rbx and rbp are saved and restored by hand, every other register is
    // declared as clobbered, and the only memory written is `out`.
    unsafe {
        asm!(
            "push rbx",
            "push rbp",
            "push rdi",                // pointer to `out`
            "mov rbx, {p}", "add rbx, 1",
            "mov rbp, {p}", "add rbp, 2",
            "mov rdi, {p}", "add rdi, 3",
            "mov rsi, {p}", "add rsi, 4",
            "mov rdx, {p}", "add rdx, 5",
            "mov r8,  {p}", "add r8,  6",
            "mov r9,  {p}", "add r9,  7",
            "mov r10, {p}", "add r10, 8",
            "mov r12, {p}", "add r12, 9",
            "mov r13, {p}", "add r13, 10",
            "mov r14, {p}", "add r14, 11",
            "mov r15, {p}", "add r15, 12",
            "mov r11, {p}",
            // Either spin (to be preempted by the timer) or enter the kernel.
            "test rcx, rcx",
            "jz 3f",
            "2:",
            "dec rcx",
            "jnz 2b",
            "jmp 4f",
            "3:",
            "syscall",
            "4:",
            "mov rcx, [rsp]",
            "mov [rcx + 0x00], rax",
            "mov [rcx + 0x08], rbx",
            "mov [rcx + 0x10], rbp",
            "mov [rcx + 0x18], rdi",
            "mov [rcx + 0x20], rsi",
            "mov [rcx + 0x28], rdx",
            "mov [rcx + 0x30], r8",
            "mov [rcx + 0x38], r9",
            "mov [rcx + 0x40], r10",
            "mov [rcx + 0x48], r11",
            "mov [rcx + 0x50], r12",
            "mov [rcx + 0x58], r13",
            "mov [rcx + 0x60], r14",
            "mov [rcx + 0x68], r15",
            "add rsp, 8",
            "pop rbp",
            "pop rbx",
            p = const PATTERN,
            inout("rdi") out.as_mut_ptr() => _,
            inout("rax") nr => _,
            inout("rcx") spin => _,
            out("rsi") _, out("rdx") _, out("r8") _, out("r9") _, out("r10") _, out("r11") _,
            out("r12") _, out("r13") _, out("r14") _, out("r15") _,
        );
    }
    out
}

fn looks_like_kernel_value(v: u64) -> bool {
    v >= 0x0000_8000_0000_0000
}

fn register_integrity() -> u64 {
    // (system call number, spin count, registers the call is allowed to change)
    let cases: [(u64, u64, &[usize]); 5] = [
        (abi::sys::YIELD, 0, &[0, 9]),
        (0xdead_beef, 0, &[0, 9]),                 // unknown system call
        (abi::sys::CAP_INFO, 0, &[0, 3, 4, 5, 9]), // returns rdi, rsi, rdx
        (abi::sys::RANDOM, 0, &[0, 3, 9]),         // returns rdi
        (PATTERN, 400_000_000, &[]),               // preempted many times, no syscall
    ];
    for (case, &(nr, spin, may_change)) in cases.iter().enumerate() {
        let rounds = if spin == 0 { 200 } else { 1 };
        for _ in 0..rounds {
            let regs = registers_after(nr, spin);
            let expected = [
                nr,
                PATTERN + 1,
                PATTERN + 2,
                PATTERN + 3,
                PATTERN + 4,
                PATTERN + 5,
                PATTERN + 6,
                PATTERN + 7,
                PATTERN + 8,
                PATTERN,
                PATTERN + 9,
                PATTERN + 10,
                PATTERN + 11,
                PATTERN + 12,
            ];
            for (i, (&got, &want)) in regs.iter().zip(&expected).enumerate() {
                // `random` legitimately returns arbitrary bits in rdi.
                let random_value = nr == abi::sys::RANDOM && i == 3;
                if looks_like_kernel_value(got) && !random_value {
                    println!("  register {i} holds a kernel value after case {case}: {got:#x}");
                    return selftest::EXIT_CHECK_FAILED | (0x100 + i as u64);
                }
                if got != want && !may_change.contains(&i) {
                    println!("  register {i} changed in case {case}: {got:#x} != {want:#x}");
                    return selftest::EXIT_CHECK_FAILED | (0x200 + i as u64);
                }
            }
        }
    }
    selftest::EXIT_OK
}

/// Entry point for every probe role.
pub fn run(mode: u64) -> ! {
    let code = match mode {
        mode::SINGLE_STEP_SYSCALL => single_step_syscall(),
        mode::HOSTILE_STACK_AND_FLAGS => hostile_stack_and_flags(),
        mode::SEGMENT_REGISTERS => segment_registers(),
        mode::REGISTER_INTEGRITY => register_integrity(),
        // Exit straight away: the supervisor must still learn about it.
        mode::SILENT_EXIT => selftest::EXIT_SILENT,
        _ => attack(mode).unwrap_or(selftest::EXIT_ESCAPED),
    };
    k::thread_exit(code)
}
