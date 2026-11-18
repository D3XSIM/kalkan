//! Protocol shared by the root task and the untrusted processes in the self-test
//! suite.
//!
//! Every instance of the sandbox image first asks its supervisor which role it
//! plays (`HELLO`). The *main* sandbox runs the non-fatal escape attempts; every
//! *probe* performs exactly one attack that the CPU or the kernel must stop, and
//! the supervisor checks that the probe was terminated in exactly the expected way.
//! The last few probes take part in process life-cycle tests instead (calls that
//! can never be answered, processes that die while nobody listens, processes
//! killed from outside).
//!
//! Probes exist only in test kernels (`selftest` feature).

/// Badge of the main sandbox's client capability to the root task's endpoint.
pub const CLIENT_BADGE: u64 = 0xc11e47;
/// Badge the kernel delivers with the main sandbox's fault reports.
pub const FAULT_BADGE: u64 = 0xfa017;
/// Client badge of probe `i` is `PROBE_CLIENT_BADGE + i`.
pub const PROBE_CLIENT_BADGE: u64 = 0x9b0b_e000;
/// Fault badge of probe `i` is `PROBE_FAULT_BADGE + i`.
pub const PROBE_FAULT_BADGE: u64 = 0xfa17_e000;

/// `[HELLO, 0, 0, 0]` → reply `[mode, argument, argument2, 0]`.
///
/// The main sandbox gets the addresses of kernel data and of the kernel's direct
/// map (0 on kernels that do not reveal them), a memory probe the address it
/// attacks, the fuzzer its seed.
pub const HELLO: u64 = 0x4b48_454c_4c4f;
/// `[ABANDON, 0, 0, 0]`, sent with `call`: the supervisor receives it and then
/// receives again without replying, which must release the caller with `EDEAD`.
pub const ABANDON: u64 = 0x4b41_4241_4e44;
/// `[HOLD, 0, 0, 0]`: the call a server probe receives and never answers.
pub const HOLD: u64 = 0x4b48_4f4c_4400;
/// `[REPORT, test_id, passed, 0]`.
pub const REPORT: u64 = 0x4b52_4550_4f52;
/// `[TRANSFER, 0, 0, 0]` + a capability; the reply carries the message info flags.
pub const TRANSFER: u64 = 0x4b54_5246_4552;
/// `[DONE, tests, 0, 0]`.
pub const DONE: u64 = 0x4b44_4f4e_4500;
/// `[MARK, n, 0, 0]`: the supervisor samples the kernel's resource statistics.
pub const MARK: u64 = 0x4b4d_4152_4b00;
/// Text the root task places in the read-only shared page.
pub const SHARED_SECRET: &[u8; 20] = b"kalkan-shared-memory";

/// Exit code of a probe whose (non-fatal) checks all passed.
pub const EXIT_OK: u64 = 0x600d;
/// Exit code of a probe whose attack was **not** stopped.
pub const EXIT_ESCAPED: u64 = 0xe5ca_9ed0;
/// Exit code of a probe whose check found a problem (the low bits say which).
pub const EXIT_CHECK_FAILED: u64 = 0xbad_0000;
/// Exit code when the CPU lacks the feature under test (reported as N/A).
pub const EXIT_NOT_APPLICABLE: u64 = 0x0a0a;
/// Exit code used by the "exit without telling anyone" probe.
pub const EXIT_SILENT: u64 = 0x5117;

/// Capability slots in a sandbox's CSpace (granted by the root task).
///
/// Slots 3–5 are deliberately left empty: they are the root task's untyped,
/// console and thread slots, which the sandbox tries to use.
pub mod slot {
    /// Send-only, badged endpoint to the root task.
    pub const ENDPOINT: u64 = 1;
    /// Console, `WRITE` only (cannot be passed on).
    pub const CONSOLE: u64 = 2;
    /// Read-only shared frame (main sandbox) / private frame (fuzzer).
    pub const SHARED_FRAME: u64 = 6;
    /// The sandbox's own address space (map rights only).
    pub const VSPACE: u64 = 7;
    /// First free slot.
    pub const FIRST_FREE: u64 = 8;
    /// Fuzzer only: a delegated untyped budget.
    pub const FUZZ_UNTYPED: u64 = 9;
    /// Life-cycle probes only: receive right on an endpoint the supervisor calls.
    pub const SERVER_EP: u64 = 10;
}

/// x86 exception vectors.
pub mod vector {
    pub const DIVIDE_ERROR: u64 = 0;
    pub const DEBUG: u64 = 1;
    pub const INVALID_OPCODE: u64 = 6;
    pub const DEVICE_NOT_AVAILABLE: u64 = 7;
    pub const GENERAL_PROTECTION: u64 = 13;
    pub const PAGE_FAULT: u64 = 14;
}

/// Page fault error code bits.
pub mod pf {
    /// The page was present (protection violation rather than a missing page).
    pub const PRESENT: u64 = 1 << 0;
    /// The access was a write.
    pub const WRITE: u64 = 1 << 1;
    /// The access came from user mode.
    pub const USER: u64 = 1 << 2;
    /// The access was an instruction fetch.
    pub const FETCH: u64 = 1 << 4;
}

/// Roles of a sandbox instance.
pub mod mode {
    /// The main sandbox: non-fatal escape attempts, then a kernel memory read.
    pub const MAIN: u64 = 0;
    pub const WRITE_KERNEL: u64 = 1;
    pub const READ_PHYSMAP: u64 = 2;
    pub const EXEC_KERNEL: u64 = 3;
    pub const WRITE_CODE: u64 = 4;
    pub const WRITE_RODATA: u64 = 5;
    pub const EXEC_STACK: u64 = 6;
    pub const EXEC_DATA: u64 = 7;
    pub const NULL_DEREF: u64 = 8;
    pub const STACK_OVERFLOW: u64 = 9;
    pub const NONCANONICAL_READ: u64 = 10;
    pub const NONCANONICAL_JUMP: u64 = 11;
    pub const HLT: u64 = 12;
    pub const CLI: u64 = 13;
    pub const WRMSR: u64 = 14;
    pub const RDMSR: u64 = 15;
    pub const READ_CR3: u64 = 16;
    pub const WRITE_CR4: u64 = 17;
    pub const PORT_OUT: u64 = 18;
    pub const PORT_IN: u64 = 19;
    pub const LIDT: u64 = 20;
    pub const LGDT: u64 = 21;
    pub const LTR: u64 = 22;
    pub const INT_0X80: u64 = 23;
    pub const INT3: u64 = 24;
    pub const INT_TIMER: u64 = 25;
    pub const RDTSC: u64 = 26;
    pub const RDPMC: u64 = 27;
    pub const SGDT: u64 = 28;
    pub const SIDT: u64 = 29;
    pub const SSE: u64 = 30;
    pub const X87: u64 = 31;
    pub const AVX: u64 = 32;
    pub const XSETBV: u64 = 33;
    pub const WRGSBASE: u64 = 34;
    pub const IRET_TO_RING0: u64 = 35;
    pub const RETF_TO_RING0: u64 = 36;
    pub const LOAD_KERNEL_SS: u64 = 37;
    pub const SYSENTER: u64 = 38;
    pub const DIVIDE_BY_ZERO: u64 = 39;
    pub const UD2: u64 = 40;
    pub const SINGLE_STEP: u64 = 41;
    pub const SINGLE_STEP_SYSCALL: u64 = 42;
    pub const HOSTILE_STACK_AND_FLAGS: u64 = 43;
    pub const SEGMENT_REGISTERS: u64 = 44;
    pub const REGISTER_INTEGRITY: u64 = 45;
    pub const SILENT_EXIT: u64 = 46;
    pub const FUZZ: u64 = 47;
    pub const READ_KERNEL_CODE: u64 = 48;
    pub const READ_KERNEL_DATA: u64 = 49;
    pub const READ_KERNEL_STACK: u64 = 50;
    pub const READ_KERNEL_HEAP: u64 = 51;
    pub const WRITE_KERNEL_CODE: u64 = 52;
    pub const WRITE_KERNEL_STACK: u64 = 53;
    pub const WRITE_PHYSMAP: u64 = 54;
    // Process life cycle.
    /// Calls the supervisor, which abandons the call.
    pub const ABANDONED_CALL: u64 = 60;
    /// Receives a call and exits without answering it.
    pub const SERVER_DIES: u64 = 61;
    /// Exits at once, while nobody receives its report.
    pub const ZOMBIE: u64 = 62;
    /// Exits at once; nobody can ever receive its report.
    pub const ORPHANED_REPORT: u64 = 63;
    /// Spins until it is killed.
    pub const SPIN: u64 = 64;
    /// Blocks in `recv` until it is killed.
    pub const BLOCK: u64 = 65;
}

/// Kernel memory a probe attacks. The supervisor looks the address up with
/// `kernel_layout` and hands it to the probe, so that the attack hits live kernel
/// memory wherever KASLR placed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// The probe does not attack kernel memory.
    None,
    /// Kernel code.
    Code,
    /// Kernel writable data.
    Data,
    /// The kernel stack.
    Stack,
    /// A live kernel heap object.
    Heap,
    /// The kernel image through the kernel's direct map of physical memory.
    DirectMap,
}

/// How a probe is expected to end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expect {
    /// Killed by this exception; for page faults `error_bits` must all be set.
    Fault { vector: u64, error_bits: u64 },
    /// Killed by a page fault at exactly the attacked kernel address, with all
    /// `error_bits` set. They always include `pf::PRESENT`: the page *is* mapped,
    /// so it was the privilege check that stopped the access, not a missing page.
    KernelFault { error_bits: u64 },
    /// Killed by one of two exceptions (CPU vendors differ).
    FaultEither(u64, u64),
    /// Killed by this exception, or "not applicable" if the CPU lacks the feature.
    FaultOrNotApplicable(u64),
    /// Exits voluntarily with this code.
    Exit(u64),
}

/// One fault-containment test.
#[derive(Clone, Copy, Debug)]
pub struct Probe {
    /// Role handed to the probe process.
    pub mode: u64,
    /// What the probe attempts.
    pub name: &'static str,
    /// The kernel memory it attacks, if any.
    pub target: Target,
    /// How it must end.
    pub expect: Expect,
}

const fn probe(mode: u64, name: &'static str, expect: Expect) -> Probe {
    Probe {
        mode,
        name,
        target: Target::None,
        expect,
    }
}

const fn fault(mode: u64, name: &'static str, vector: u64) -> Probe {
    probe(
        mode,
        name,
        Expect::Fault {
            vector,
            error_bits: 0,
        },
    )
}

const fn page_fault(mode: u64, name: &'static str, error_bits: u64) -> Probe {
    probe(
        mode,
        name,
        Expect::Fault {
            vector: vector::PAGE_FAULT,
            error_bits,
        },
    )
}

const fn kernel_fault(mode: u64, name: &'static str, target: Target, access: u64) -> Probe {
    Probe {
        mode,
        name,
        target,
        expect: Expect::KernelFault {
            error_bits: pf::PRESENT | pf::USER | access,
        },
    }
}

const fn exits(mode: u64, name: &'static str, code: u64) -> Probe {
    probe(mode, name, Expect::Exit(code))
}

use vector::{GENERAL_PROTECTION as GP, INVALID_OPCODE as UD};

/// Number of probe processes used by the process life-cycle tests (the last ones).
pub const LIFECYCLE_PROBES: usize = 6;

/// Number of fault-containment tests (the first probe processes).
pub const ATTACKS: usize = kcore::abi::PROBE_COUNT as usize - LIFECYCLE_PROBES;

/// Every fault-containment test, in the order they are run.
pub const PROBES: [Probe; ATTACKS] = [
    // --- kernel memory at its real (randomised) addresses, enforced by the MMU
    kernel_fault(mode::READ_KERNEL_CODE, "read kernel code", Target::Code, 0),
    kernel_fault(
        mode::WRITE_KERNEL_CODE,
        "overwrite kernel code",
        Target::Code,
        pf::WRITE,
    ),
    kernel_fault(
        mode::EXEC_KERNEL,
        "jump to kernel code",
        Target::Code,
        pf::FETCH,
    ),
    kernel_fault(mode::READ_KERNEL_DATA, "read kernel data", Target::Data, 0),
    kernel_fault(
        mode::WRITE_KERNEL,
        "write to kernel data",
        Target::Data,
        pf::WRITE,
    ),
    kernel_fault(
        mode::READ_KERNEL_STACK,
        "read the kernel stack",
        Target::Stack,
        0,
    ),
    kernel_fault(
        mode::WRITE_KERNEL_STACK,
        "overwrite the kernel stack",
        Target::Stack,
        pf::WRITE,
    ),
    kernel_fault(
        mode::READ_KERNEL_HEAP,
        "read a kernel heap object",
        Target::Heap,
        0,
    ),
    kernel_fault(
        mode::READ_PHYSMAP,
        "read the kernel through the direct map of physical memory",
        Target::DirectMap,
        0,
    ),
    kernel_fault(
        mode::WRITE_PHYSMAP,
        "write the kernel through the direct map of physical memory",
        Target::DirectMap,
        pf::WRITE,
    ),
    // --- memory isolation within the process
    page_fault(
        mode::WRITE_CODE,
        "overwrite its own code (W^X)",
        pf::PRESENT | pf::WRITE | pf::USER,
    ),
    page_fault(
        mode::WRITE_RODATA,
        "overwrite its own read-only data",
        pf::PRESENT | pf::WRITE | pf::USER,
    ),
    page_fault(
        mode::EXEC_STACK,
        "execute code on its stack (NX)",
        pf::PRESENT | pf::FETCH | pf::USER,
    ),
    page_fault(
        mode::EXEC_DATA,
        "execute its writable data (NX)",
        pf::PRESENT | pf::FETCH | pf::USER,
    ),
    page_fault(mode::NULL_DEREF, "dereference a null pointer", pf::USER),
    page_fault(
        mode::STACK_OVERFLOW,
        "overflow its stack into the guard page",
        pf::WRITE | pf::USER,
    ),
    fault(mode::NONCANONICAL_READ, "read a non-canonical address", GP),
    fault(
        mode::NONCANONICAL_JUMP,
        "jump to a non-canonical address",
        GP,
    ),
    // --- privileged instructions
    fault(mode::HLT, "halt the CPU (hlt)", GP),
    fault(mode::CLI, "disable interrupts (cli)", GP),
    fault(
        mode::WRMSR,
        "redirect the system call entry (wrmsr LSTAR)",
        GP,
    ),
    fault(
        mode::RDMSR,
        "read the kernel entry address (rdmsr LSTAR)",
        GP,
    ),
    fault(
        mode::READ_CR3,
        "read the page table root (mov from cr3)",
        GP,
    ),
    fault(mode::WRITE_CR4, "disable SMEP/SMAP (mov to cr4)", GP),
    fault(
        mode::PORT_OUT,
        "reset the machine through an I/O port (out)",
        GP,
    ),
    fault(mode::PORT_IN, "read an I/O port (in)", GP),
    fault(mode::LIDT, "install its own interrupt table (lidt)", GP),
    fault(mode::LGDT, "install its own descriptor table (lgdt)", GP),
    fault(mode::LTR, "load the task register (ltr)", GP),
    // --- interrupt vectors are not callable from user mode
    fault(mode::INT_0X80, "invoke an interrupt vector (int 0x80)", GP),
    fault(mode::INT3, "invoke the breakpoint vector (int3)", GP),
    fault(mode::INT_TIMER, "fake a timer interrupt (int 32)", GP),
    // --- timing and address disclosure
    fault(mode::RDTSC, "read the time stamp counter (rdtsc)", GP),
    fault(mode::RDPMC, "read a performance counter (rdpmc)", GP),
    probe(
        mode::SGDT,
        "read the GDT address (sgdt, UMIP)",
        Expect::FaultOrNotApplicable(GP),
    ),
    probe(
        mode::SIDT,
        "read the IDT address (sidt, UMIP)",
        Expect::FaultOrNotApplicable(GP),
    ),
    // --- CPU state the kernel does not save
    fault(mode::SSE, "use SSE registers", UD),
    fault(mode::X87, "use the x87 FPU", vector::DEVICE_NOT_AVAILABLE),
    fault(mode::AVX, "use AVX registers", UD),
    probe(
        mode::XSETBV,
        "enable extended state (xsetbv)",
        Expect::FaultEither(UD, GP),
    ),
    fault(mode::WRGSBASE, "change the GS base (wrgsbase)", UD),
    // --- privilege level games
    fault(mode::IRET_TO_RING0, "iretq into ring 0", GP),
    fault(
        mode::RETF_TO_RING0,
        "far return into the kernel code segment",
        GP,
    ),
    fault(mode::LOAD_KERNEL_SS, "load the kernel stack segment", GP),
    probe(
        mode::SYSENTER,
        "enter the kernel through sysenter",
        Expect::FaultEither(GP, UD),
    ),
    // --- ordinary crashes are contained too
    fault(mode::DIVIDE_BY_ZERO, "divide by zero", vector::DIVIDE_ERROR),
    fault(mode::UD2, "execute an undefined instruction", UD),
    fault(
        mode::SINGLE_STEP,
        "single-step itself (trap flag)",
        vector::DEBUG,
    ),
    // --- hostile but legal behaviour: the kernel must stay correct
    exits(
        mode::SINGLE_STEP_SYSCALL,
        "system call with the trap flag set",
        EXIT_OK,
    ),
    exits(
        mode::HOSTILE_STACK_AND_FLAGS,
        "system calls with a hostile stack pointer and flags",
        EXIT_OK,
    ),
    exits(
        mode::SEGMENT_REGISTERS,
        "system calls after reloading FS and GS",
        EXIT_OK,
    ),
    exits(
        mode::REGISTER_INTEGRITY,
        "registers survive system calls and preemption, no kernel values leak",
        EXIT_OK,
    ),
    exits(
        mode::SILENT_EXIT,
        "exit without notifying anyone",
        EXIT_SILENT,
    ),
    exits(mode::FUZZ, "system call fuzzer", EXIT_OK),
];
