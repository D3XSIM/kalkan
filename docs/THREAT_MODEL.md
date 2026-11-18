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
| No authority without a capability | Per-process CSpaces; no global names; every system call looks up a capability with an explicit required right |
| Authority can only shrink | `Rights::derive` subset rule (exhaustively tested), write-once badges, GRANT for cross-domain transfer |
| Authority can be withdrawn | Derivation tree, transitive revocation across CSpaces, revocation also removes frame mappings |
| No confused-deputy via pointers | User memory is accessed only after a page-table walk of the *caller's* address space with user-permission checks; kernel addresses can never be named |
| Memory isolation | Separate address spaces, supervisor-only kernel half, SMEP/SMAP, NX, W^X, zeroed frames |
| Kernel integrity | Rust memory safety, `unsafe` confined and documented, W^X kernel image, write-protect (CR0.WP), guard pages, IST stacks, hardened heap, overflow checks, fail-closed panics |
| Register / microarchitectural state | GPRs scrubbed on entry and restored only from saved user state; SIMD disabled; `lfence` after `swapgs`; IBPB on address-space switch; VERW on return; Spectre-v1 index clamping; `rdtsc` privileged |
| Address secrecy | KASLR; randomised physmap, stack, heap and MMIO regions; user ASLR; UMIP |
| Availability | Kernel never blocks; every user-triggerable error returns an error code; untyped budgets (revocable together with everything built from them); per-address-space page-table quota with reclamation of empty tables; a kernel frame reserve that user activity can never consume; hard limits on all kernel tables; supervised threads report their exit to their supervisor |
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
* **Not formally verified.** The capability model is tested and fuzzed, not proven.
