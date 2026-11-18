# Threat model

## Assets

1. **Kernel integrity** — kernel code, data, page tables and control flow.
2. **Kernel confidentiality** — kernel memory contents and addresses (KASLR).
3. **Isolation between processes** — memory, capabilities, CPU register state.
4. **Authority** — who holds which capability with which rights.
5. **Availability** of the kernel (it must not crash or hang because of user input).
6. **Boot integrity** — the kernel and the user programs that run are the ones
   that were built.

## Adversaries

| Adversary | Capabilities | In scope |
|---|---|---|
| **Malicious process** | Arbitrary code at CPL 3, any system call with any arguments, holds whatever capabilities it was legitimately granted | ✅ primary adversary |
| **Compromised server** | A process holding more capabilities (e.g. a badged client endpoint) trying to exceed them | ✅ |
| **Boot partition tampering** | Can modify files on the boot medium | ✅ partially (see below) |
| Malicious bootloader / firmware | — | ❌ trusted |
| Physical attacker, DMA-capable device | — | ❌ (no IOMMU support yet) |
| Root task (`init`) | — | ❌ trusted by definition: it receives all initial authority |

## Trust boundaries

```text
 untrusted ─► system call / exception / interrupt entry ─► kernel
 untrusted ─► ELF images (validated before use)          ─► loader
 untrusted ─► boot partition contents (hash-verified)    ─► bootloader + kernel
```

## Mitigations

| Goal | Mechanism |
|---|---|
| No authority without a capability | Per-process CSpaces; no global names; every system call looks up a capability with an explicit required right — even randomness (an entropy capability) and terminating other threads (a thread capability) |
| Authority can only shrink | `Rights::derive` subset rule (exhaustively tested), write-once badges, GRANT for cross-domain transfer |
| Authority can be withdrawn | Derivation tree, transitive revocation across CSpaces, revocation also removes frame mappings |
| No confused-deputy via pointers | User memory is accessed only after a page-table walk of the *caller's* address space with user-permission checks; kernel addresses can never be named |
| Memory isolation | Separate address spaces, supervisor-only kernel half, SMEP/SMAP, NX, W^X, zeroed frames |
| Kernel integrity | Rust memory safety, `unsafe` confined and documented, W^X kernel image, write-protect (CR0.WP), guard pages, IST stacks (incl. `#DB`), hardened heap, overflow checks, fail-closed panics, a self-audit of the whole object graph (page tables checked in both directions) |
| Register / microarchitectural state | GPRs scrubbed on entry and restored only from saved user state; SIMD disabled; `lfence` after `swapgs`; IBPB on address-space switch; VERW on return; Spectre-v1 index clamping; `rdtsc` privileged |
| Address secrecy | KASLR; the kernel relocates its direct map of physical memory to a random address; randomised stack, heap and MMIO regions; user ASLR; UMIP; no addresses in the kernel log |
| Availability | Kernel never blocks; every user-triggerable error returns an error code; untyped budgets (revocable together with everything built from them); per-address-space page-table quota with reclamation of empty tables; a kernel frame reserve that user activity can never consume; hard limits on all kernel tables, sized so that no process can exhaust them for the others; supervised threads report their exit to their supervisor; a dead thread releases its memory at once, even if its report is never collected; calls that can no longer be answered return `EDEAD`; supervisors can kill the threads they hold capabilities to |
| Boot integrity | Pinned bootloader (tag, commit, digest); BLAKE2b-512 of kernel and modules checked by Limine; module digests compiled into the kernel and re-checked; tamper test in CI |
| Supply chain | No third-party crates in the kernel; `cargo-deny`; CI actions pinned to commit SHAs; minimal workflow permissions |

## Known limitations

These are deliberate scope cuts of version 0.1 — please do not report them as
vulnerabilities, but contributions are very welcome.

* **Single CPU.** There is no SMP support; the design (non-preemptible kernel with
  one lock) would need per-CPU stacks, IPIs and TLB shootdowns.
* **No IOMMU.** Malicious DMA-capable hardware can read and write all memory.
* **No KPTI.** CPUs affected by Meltdown (CVE-2017-5754) could leak kernel memory
  to user space. Modern CPUs are not affected.
* **Spectre v1 hardening is best effort.** Indices from user space are clamped
  with a branch-free mask hidden from the optimiser by `core::hint::black_box`,
  but there is no compiler-wide speculative load hardening.
* **No shadow stacks / CFI** for the kernel yet (Intel CET, kCFI need nightly
  Rust or more work).
* **Page tables for user mappings are not charged** to an untyped budget. They
  are bounded instead: at most 64 table frames per address space, empty tables
  are freed on unmap, and all user-driven allocations stop short of a 4 MiB
  kernel reserve.
* **KASLR on CPUs without UMIP.** Without UMIP, `sgdt`/`sidt`/`str` reveal the
  addresses of the GDT, IDT and TSS, which are kernel statics, and therefore the
  KASLR slide.
* **Spectre v2 relies on hardware.** IBRS/STIBP are enabled when available; there
  are no retpolines (they need nightly Rust) and no RSB stuffing on entry.
* **The debug console is not rate limited.** A process holding a console
  capability can flood the serial line.
* **Covert/timing channels** between processes (cache, scheduling) are not
  addressed beyond restricting `rdtsc`.
* **Boot integrity without Secure Boot is only as strong as the boot medium.** An
  attacker who can rewrite the boot partition can replace the kernel *and* its
  compiled-in digests. Enabling UEFI Secure Boot with a signed Limine and an
  enrolled config hash (`limine enroll-config`) closes this gap.
* **Error codes check rights before type.** A capability of the wrong type that
  also lacks the required right yields `EPERM`, not `ETYPE`. Both are refusals;
  the caller learns nothing it cannot read with `cap_info` on its own slot.
* **Never run on real hardware yet.** The suite runs under QEMU's TCG, which does
  not implement IBRS/STIBP (`spec-ctrl`): that code path has never executed.
  Mitigations for hardware side channels (IBRS, STIBP, IBPB, VERW) are enabled
  when the CPU offers them, but their effect is not measured. Both local APIC
  modes (x2APIC and xAPIC) are exercised.
* **No process creation from user space.** All processes are created by the
  kernel at boot from verified modules; there is no `spawn` system call yet. A
  supervisor can stop processes (`thread_kill`) but not start new ones.
* **Test kernels are for testing only.** A kernel built with the `selftest`
  feature reveals its layout (`kernel_layout`, addresses in the log) and creates
  probe processes. `cargo xtask build` never enables it; CI checks that a normal
  kernel has none of these.
* **Debug traps from user mode are handled on an IST stack.** A `#DB` raised by a
  user process (trap flag, `icebp`) runs the kernel's trap path on its dedicated
  16 KiB stack rather than the 64 KiB kernel stack. That path is short and no
  debug trap ever reaches kernel mode (the suite counts them), but moving such
  traps to the kernel stack, as Linux does, would be more robust.
* **Not formally verified.** The capability model is tested against a reference
  model and fuzzed, not proven.
