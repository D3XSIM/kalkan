# Kalkan architecture

## Overview

Kalkan is a single-CPU, x86-64 microkernel. The kernel implements five object
types — **threads, endpoints, address spaces (VSpaces), frames and untyped memory
budgets** — plus the capabilities that name them. Everything else (drivers, file
systems, servers) is meant to live in user space.

```text
            ┌──────────────────────────┐   ┌──────────────────────────┐
 CPL 3      │ init (root task)         │   │ sandbox (untrusted)      │
            │ CSpace: 6 initial caps   │◄──┤ CSpace: 4 granted caps   │
            │ own address space        │IPC│ own address space        │
            └────────────┬─────────────┘   └────────────┬─────────────┘
 ═══════════════════════ │ syscall / interrupt / fault ══│═══════════════════
            ┌────────────▼──────────────────────────────▼─────────────┐
 CPL 0      │ entry stubs: swapgs+lfence, clac, register scrubbing    │
            │ kernel::user_trap → syscall / IPC / fault / scheduler   │
            │ kcore: capability DB · rights · ELF · crypto (no unsafe)│
            │ mm: frames · W^X page tables · heap · user-memory copy  │
            │ arch: GDT/TSS/IDT · CPU hardening · APIC · entropy      │
            └─────────────────────────────────────────────────────────┘
```

### Trusted computing base

| Component | `unsafe` | Notes |
|---|---|---|
| `kcore` | forbidden | Capability database, rights, ELF validation, BLAKE2b, ChaCha20, bitmap, Spectre clamping |
| `kernel/src/kernel` | denied | Objects, scheduler, IPC, system calls, loader — written against safe interfaces only |
| `kernel/src/arch` | allowed, documented | Assembly entry paths, descriptor tables, MSRs, control registers |
| `kernel/src/mm` | allowed, documented | Page tables, direct-map access, heap |
| `kernel/src/boot.rs` | allowed, documented | Limine protocol structures |
| `kernel/src/sync.rs` | allowed, documented | Spin lock |
| Limine | — | Pinned binary, verified by tag, commit and BLAKE2b |

## Boot sequence

1. **Limine** loads the kernel at a random address (KASLR). Before loading, it verifies the BLAKE2b-512 digest of the kernel
   and of every module listed in `limine.conf`.
2. **Stage 1** (`boot_main`, on the bootloader's stack and page tables):
   serial log → GDT/TSS (with early IST stacks) → IDT → CPU feature detection →
   **hardening** (`cpu::harden`; fail-closed without NX/SMEP/SMAP) → entropy
   gathering → frame allocator → construction of the kernel's own page tables.
3. The kernel switches **page tables and stack in one instruction sequence** to
   its own guard-paged stack.
4. **Stage 2** (`stage2`): the TSS is pointed at the guarded kernel and IST
   stacks (they exist only in the kernel's own page tables) → heap → `syscall`
   MSRs → local APIC (x2APIC mode whenever the CPU supports it, xAPIC otherwise)
   → **security self check** (`posture::verify` reads back control registers and
   walks its own page tables) → **module verification** against digests compiled
   into the kernel → creation of `init` and `sandbox` → reclaiming (and zeroing)
   bootloader memory → first entry to user mode.

## Memory

### Kernel address space

| Region | Permissions | Placement |
|---|---|---|
| Kernel `.text` | `R-X` | KASLR (Limine) |
| Kernel `.rodata` (incl. relocated `.data.rel.ro`, `.got`) | `R--` | KASLR |
| Kernel `.data`/`.bss` | `RW-` NX | KASLR |
| Direct map of RAM | `RW-` NX (`R--` for the kernel image's own frames) | random PML4 slot + random 1 GiB offset, chosen by the kernel |
| Kernel stack (64 KiB) + 4 IST stacks (16 KiB: #DF, NMI, #MC, #DB) | `RW-` NX, guard page between each | random PML4 slot + random offset |
| Heap (64 GiB virtual) | `RW-` NX | random PML4 slot + random offset |
| Local APIC (xAPIC mode only; in x2APIC mode its registers are MSRs and nothing is mapped) | `RW-` NX, uncached | random PML4 slot + random offset |

The heap's top-level page-table entry is created at boot, so every address space
created later shares it. No kernel mapping has the `USER` bit.

None of these addresses appears in the kernel's log: it prints `<hidden>`
instead (test kernels excepted, see [below](#test-kernels)).

The bootloader's own direct map sits at a predictable address, so the kernel does
not keep it: it builds a new one at a random location and switches to it together
with its page tables. Boot modules are recorded as physical ranges beforehand, and
the frame allocator is re-attached to its bitmap through the new mapping.

### Physical memory

`kcore::bitmap::FrameBitmap` tracks every 4 KiB frame. All frames start *used* and
are released from the firmware memory map, so unknown memory is never handed out.
Frames are zeroed on allocation and on free; double frees are fatal. Allocations
made on behalf of user space (objects, user page tables, program images) can never
dip into a reserve of 1024 frames kept for the kernel itself, so user activity can
never make a kernel allocation fail.

### Heap

A segregated-fit allocator with size classes 16 B – 2 KiB plus page-granular large
allocations (each followed by an unmapped guard page). Free-list pointers are
*safe-linked* (XOR with a per-boot secret and the block address) and validated on
every pop; freed blocks are poisoned and checked on reuse.

### User address spaces

The lower half (`0x40_0000 .. 0x7fff_ffff_0000`) is private to each process. The
upper half shares the kernel's page tables, which are supervisor-only. User
mappings are W^X by construction (`UserPerms` cannot represent W+X), and W^X also
holds per *frame*: the kernel counts writable and executable mappings of every
frame and refuses a mapping that would make the same frame writable in one place
and executable in another.

Page tables of an address space are limited to 64 frames, and `unmap` frees every
intermediate table that becomes empty, so mapping and unmapping at ever new
addresses cannot consume kernel memory.

Programs are position independent. The loader validates them with
`kcore::elf::parse`, places them at a random base inside a 1 TiB window, copies
segments into fresh zeroed frames, applies `R_X86_64_RELATIVE` relocations, maps
each page with its segment's permissions and creates a 64 KiB stack at a random
address with an unmapped guard page below.

### Accessing user memory

The kernel **never dereferences a user pointer**. `AddressSpace::copy_from_user`
validates the range against the user window, walks the page tables of the target
address space, requires every page to be present and user-accessible, and copies
through the direct map. SMAP therefore stays enabled permanently.

## Execution model

* **One kernel stack, event driven.** Every entry from user mode pushes a
  `TrapFrame` at the top of the kernel stack. `kernel::user_trap` saves it into
  the current thread, handles the event to completion, picks the next thread and
  overwrites the frame with that thread's registers. The common exit path restores
  it and executes `iretq`.
* **Interrupts are disabled in kernel mode.** The kernel is never preempted and
  never sleeps; a trap taken *in* kernel mode is a bug and panics.
* **Preemption** of user threads comes from the local APIC timer.
* **Entry hardening:** `swapgs` only when coming from user mode, followed by
  `lfence`; `clac`; `cld`; all general purpose registers zeroed before Rust code
  runs. **Exit hardening:** CS/SS forced to user selectors, RFLAGS sanitised
  (IF set; IOPL, NT, AC, TF cleared), CPU buffers cleared with `verw` where
  supported. The kernel never uses `sysret`.

## Capabilities

```text
CSpace of init                 CSpace of sandbox
┌────┬──────────────────┐      ┌────┬──────────────────────┐
│  4 │ Console  -w-g    │──┐   │  1 │ Endpoint -w-- badge=c│
│ 12 │ Endpoint rw-g    │──┼──►│  2 │ Console  -w--        │
│ 14 │ Frame    rwxg    │──┼──►│  6 │ Frame    r---        │
└────┴──────────────────┘  │   │  7 │ VSpace   -w--        │
                           │   └────┴──────────────────────┘
        derivation tree ───┘   (sandbox cannot pass any of these on: no GRANT)
```

* A capability is `(object, rights, badge)`. Rights are `READ`, `WRITE`, `EXEC`,
  `GRANT`.
* `mint` derives a capability with a **subset** of the rights; a badge can be set
  once, on an unbadged capability.
* Moving a capability into **another** CSpace (`thread_grant`, IPC transfer)
  requires `GRANT` on it.
* `revoke(c)` deletes every capability derived from `c`, transitively, in every
  CSpace. `delete` re-parents children, so they remain reachable by revocation.
* Frame capabilities remember where *they* mapped the frame; deleting or revoking
  the capability removes the mapping.
* Object lifetime is reference counted; ids are generational, so a stale id can
  never refer to a new object.

## IPC

Synchronous rendezvous through endpoints; no message buffering in the kernel.

| Operation | Needs | Effect |
|---|---|---|
| `send(ep, msg[4], cap?)` | `WRITE` on `ep` | Blocks until a receiver arrives |
| `recv(ep, slot?)` | `READ` on `ep` | Blocks until a sender arrives; gets badge, words, flags |
| `call(ep, msg[4], cap?)` | `WRITE` on `ep` | `send` + wait for the reply |
| `reply(msg[4])` | one-shot reply right from the last `call` received | Wakes the caller |

**Faults** are delivered as IPC: if a thread faults and has a fault endpoint, the
kernel sends `[vector, error code, address, rip]` with the badge of the fault
endpoint capability and then terminates the thread. A supervised thread that
exits voluntarily is reported the same way (`[0x100, exit code, 0, 0]`), so a
supervisor is never left waiting for a thread that is gone. Otherwise the thread is
terminated immediately. A fault never affects the kernel or other threads.

### Thread life cycle

No thread waits forever, and no dead thread keeps its resources:

* A dying thread releases its capability space, its address space and every
  capability it held **at once**. Until its report has been received, only its
  small kernel record remains (`zombie`), queued on the fault endpoint.
* A thread keeps its fault endpoint alive as a *handler*, not as a capability.
  When the last capability to an endpoint goes away, nobody can ever receive from
  it again: the endpoint is *orphaned*, every thread waiting on it is released
  with `EDEAD`, queued reports are dropped, and later reports are never queued.
* The one-shot reply right of a `call` is never lost silently: a server that
  receives again without replying, or that dies while it owes a reply, releases
  the caller with `EDEAD`.
* `thread_kill` (needs `WRITE` on the thread capability) terminates a thread from
  outside — running, ready or blocked — and unlinks it from every queue. No
  report is sent: the holder of the capability decided.
* Randomness is a capability too: `random` needs `READ` on the entropy
  capability, which the root task can pass on or withhold.

## Resource accounting

User space can only create objects (`untyped_retype`) from an *untyped* budget
capability. Every object records which budget paid for it and refunds it when it
is destroyed. Capabilities to new objects are recorded as children of the untyped
capability, so revoking a delegated budget destroys everything built from it. Kernel tables (capabilities, CSpaces, threads, endpoints, frames,
VSpaces) also have hard upper bounds, sized so that no process can exhaust them
for the others: the capability table has room for every capability space to be
full at once, and the endpoint table for every endpoint the root budget can pay
for.

## Self-audit

`kernel/src/kernel/audit.rs` can verify the complete object graph at any time:
it recounts every reference from capabilities, threads and fault handlers,
re-derives the per-frame mapping counters, compares every capability-held mapping
with the actual page tables — and, the other way round, accounts for every page
present in a user page table and recounts the page tables against the quota —
checks budget conservation, IPC queues, the call/reply bookkeeping, thread states
(including terminated threads) and the run queue, and re-checks the invariants of
the derivation tree.

It runs once before the first user instruction and once at shutdown. Built with
the `audit` feature (as `cargo xtask test` does) it runs after every trap, which
turns the adversarial test suite and the system call fuzzer into a search for
state corruption rather than just for crashes. See [TESTING.md](TESTING.md).

## Test kernels

A kernel built with the `selftest` feature (`cargo xtask run` and `cargo xtask
test` build one; `cargo xtask build` does not) differs from a normal kernel in
exactly three ways:

* besides `init` and `sandbox` it creates `PROBE_COUNT` further, inactive
  instances of the sandbox image at boot ("probes"), each with its own address
  space, capability space and ASLR layout, and hands their thread and address
  space capabilities to the root task. The test suite starts one per attack or
  life-cycle test. They are ordinary untrusted processes;
* it answers the diagnostic system calls `kernel_stats` (resource counters for
  the leak tests) and `kernel_layout` (addresses of live kernel code, data, stack,
  heap and direct map, so that the suite attacks the real kernel despite KASLR) —
  both need `READ` on the console capability, which no untrusted process gets;
* its log shows addresses instead of `<hidden>`.

A normal kernel answers both system calls with `ENOSYS`. `cargo xtask test` boots
one as well and checks all of this.

