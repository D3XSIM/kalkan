# How Kalkan is tested

Kalkan's security claims are only worth something if they are checked, so every
claim in the README is backed by a test that runs on each commit. This document
describes the layers, what each one proves, and how to extend them.

```text
cargo test -p kalkan-core -p xtask                    # host tests (seconds)
cargo test -p kalkan-core --release -- --ignored      # stress tests (seconds in release)
cargo xtask check                                     # static checks of the claims
cargo xtask test --quick                              # suite + one tamper test in QEMU (~20 s)
cargo xtask test                                      # every scenario (~2.5 min) — what CI runs
```

## 1. The policy core on the host (`kcore`)

`kcore` contains every access-control decision and is pure, `unsafe`-free Rust, so
it is tested like an ordinary library — 54 tests plus 2 stress tests.

| Technique | What it covers |
|---|---|
| **Exhaustive tests** | Every `(parent rights, requested rights)` pair: derivation can only remove rights. Every `(index, length)` pair for the Spectre index clamp on small tables. |
| **Differential model test** | The capability database is driven with random operations (`insert_root`, `insert_child`, `mint`, `delete`, `revoke`) next to a deliberately naive, independently written reference model. After *every* step the result code and the complete contents of every slot must agree. 96 000 steps per run, 1.9 million in the stress test. The arena and the frame bitmap have model tests of the same kind. |
| **Independent test vectors** | BLAKE2b is checked against RFC 7693 and against digests produced by Python's `hashlib` for lengths around every block boundary; ChaCha20 against RFC 8439 and against keystream produced by OpenSSL, including a counter near its maximum. |
| **Generators and mutation** | Random *valid* ELF images must be accepted; each single violation (W+X segment, wrapping address range, entry outside the image, ...) must be rejected with the right error; truncations and millions of random mutations must never panic, and anything accepted must satisfy W^X. |
| **Coverage-guided fuzzing** | `fuzz/` holds libFuzzer targets for the ELF validator and the capability database (run in CI). |

## 2. Static checks (`cargo xtask check`)

Cheap checks that keep the README honest:

* `Cargo.lock` contains **only** the six workspace packages — no third-party code;
* `kcore` forbids `unsafe`, the kernel denies it outside `arch`, `boot`, `mm` and
  `sync`, and no `unsafe` token appears anywhere else;
* the kernel contains no `stac`, `sysret` or `sysexit` instruction;
* every CI action is pinned to a commit hash and the workflow token is read-only;
* `docs/SYSCALLS.md` documents exactly the system calls the ABI defines.

Clippy additionally enforces a `// SAFETY:` comment on every `unsafe` block.

## 3. The kernel audits itself

`kernel/src/kernel/audit.rs` recomputes every derived quantity in the kernel from
first principles and compares it with the stored state:

* reference counts of frames, endpoints, address spaces and budgets, recounted
  from all capabilities, threads and fault handlers;
* per-frame writable/executable mapping counters, W^X per frame, and **the page
  tables themselves**, in both directions: every mapping a capability claims must
  be present with exactly those permissions and no two capabilities may claim one
  address (every audit); every page present in a user page table must belong to
  a capability mapping or to the program image the kernel loaded, must never be
  writable and executable at once, and the number of page tables must match the
  quota counter (every 64th audit, and at boot and shutdown);
* budget conservation (`remaining + outstanding charges == total`);
* IPC queues and thread states (every blocked thread is queued exactly once, no
  endpoint has senders and receivers waiting at the same time, an endpoint no
  capability refers to has nobody waiting on it);
* call/reply bookkeeping: every caller waiting for a reply is owed one by exactly
  one live thread (no lost replies);
* terminated threads waiting to deliver their report hold no capabilities and no
  address space;
* the run queue (no lost wake-ups, no duplicates);
* the structural invariants of the capability derivation tree.

`cargo xtask test` builds the kernel with the `audit` feature, which runs this
audit **after every trap** — about 44 000 times per boot — so any system call
sequence that corrupts kernel state is caught at the exact call that did it. A
regular build runs the audit once at shutdown.

## 4. The adversarial suite in QEMU

A test kernel (feature `selftest`, see
[ARCHITECTURE.md](ARCHITECTURE.md#test-kernels)) boots a root task (`user/init`)
and 61 instances of an untrusted program (`user/sandbox`). The suite currently
makes 143 checks:

* **Root task tests** — misuse of every system call from a *privileged* position:
  rights escalation, forged slots, W+X, aliasing, kernel pointers, buffers that
  cross page boundaries, budget and page-table quotas, revocation of delegated
  budgets, the entropy capability and `thread_kill`, and leak tests that compare
  the kernel's own resource counters before and after hundreds of object life
  cycles (free frames must match *exactly*: a frame freed twice or while still
  in use would show).
* **The main sandbox** — 67 escape attempts with exactly four capabilities:
  ambient authority, escalation by derivation, badge forgery, capability
  smuggling over IPC, flooding its capability space, deep derivation chains,
  memory exhaustion through page tables, hostile pointers, terminal escape
  injection — and finally a direct read of kernel memory.
* **54 probe processes** — one hardware-level attack each, because an attack that
  works kills the process: reading, writing and executing kernel code, data,
  stack, heap and the kernel's direct map **at their real, randomised addresses**
  (the test kernel tells the suite where they are), breaking W^X,
  executing the stack, stack overflow, non-canonical addresses, `hlt`, `cli`,
  `wrmsr`, `mov cr3`, port I/O, `lidt`/`lgdt`/`ltr`, `int n`, `rdtsc`, `rdpmc`,
  `sgdt`/`sidt`, SSE/x87/AVX, `xsetbv`, `wrgsbase`, `iretq`/`retf` into ring 0,
  loading kernel segments, `sysenter`, single-stepping into the kernel, system
  calls with a hostile stack pointer and flags, and more. The root task checks
  that each probe ended with exactly the expected exception and that the kernel
  got every byte and object back. Attacks on kernel memory must fault at exactly
  the attacked address with the page-present bit set: the page exists, so the
  privilege check, not a missing mapping, stopped the access.
* **6 process life-cycle tests** — a server that abandons a call or dies while it
  owes a reply (the caller must get `EDEAD`), a process whose report nobody
  receives yet (its memory must come back at once) or can ever receive (its
  fault endpoint lost its last capability: the process must vanish completely),
  and `thread_kill` on a running and on a blocked process.
* **A system call fuzzer** — 24 000 calls with adversarial arguments, steered at
  capabilities the fuzzer really holds (a frame, its address space, a memory
  budget) so that the calls reach deep into the kernel. The per-trap audit is the
  oracle.

To add an attack: add a `mode` constant and a `Probe` entry in
`user/libkalkan/src/selftest.rs`, implement it in `user/sandbox/src/probes.rs`,
and bump `PROBE_COUNT` in `kcore/src/abi.rs`.

A kernel built **without** the `selftest` feature has no probes and no
diagnostics; the root task notices and runs everything else (the rest is reported
as `[SKIP]`).

## 5. Scenarios around the suite (`xtask/src/scenarios.rs`)

| Scenario | Requirement |
|---|---|
| Test kernel with 128 MiB, 256 MiB and 5 GiB of RAM, with the local APIC in x2APIC (MSR) and in xAPIC (MMIO) mode | All 143 checks pass; the kernel audit holds; no panic; no debug trap reaches kernel mode; nothing a user process printed contains an escape sequence. |
| Normal kernel (no `selftest` feature) | No probe processes; `kernel_stats` and `kernel_layout` answer `ENOSYS`; no address anywhere in the kernel's log; every test that does not need the test facilities passes. |
| Randomisation | Kernel image, direct map, kernel stack/heap/MMIO slots, and the load addresses of `init` and `sandbox` differ between two boots of machines whose layout ranges are identical. |
| CPUs without SMEP, without SMAP, without NX | The kernel refuses to boot (fail-closed) and names the missing protection. |
| A module with one flipped byte / swapped modules / a truncated module / an extra module / a missing module (digests stripped from the bootloader config, as an attacker would) | The kernel refuses before any user code runs. |
| A kernel with one flipped byte | The bootloader never starts it and stays at its error screen. |

## 6. Review

Independent passes complement the tests: a line-by-line audit of the kernel
(which found the page-table exhaustion issue fixed in v0.1), a hands-on
penetration test from the sandbox's position — about 15 000 attack system calls,
plus runs with deliberately increased privileges — which found no way in, and a
review of the hardening changes, which found that the kernel-memory probes hit
unmapped addresses under KASLR, a missing TLB invalidation when a failed mapping
is rolled back, a capability table that a few full capability spaces could
exhaust, and reply rights that could be lost without the audit noticing. All of
these are fixed, and the suite now covers them.

## What the tests cannot show

Tests demonstrate the presence of protections, not the absence of bugs. In
particular they run on an emulated CPU that lacks some features (IBRS/STIBP), so
those code paths never execute, and hardware side channels (Spectre-class
attacks, MDS) are mitigated by design but not *measured*; and nothing here is a
formal proof. See [THREAT_MODEL.md](THREAT_MODEL.md#known-limitations).
