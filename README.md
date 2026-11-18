<div align="center">

# 🛡️ Kalkan

**A capability-based, security-first microkernel for x86-64, written in Rust.**

*Kalkan* is Turkish for *shield*.

[![CI](https://github.com/D3XSIM/kalkan/actions/workflows/ci.yml/badge.svg)](https://github.com/D3XSIM/kalkan/actions/workflows/ci.yml)
![Rust](https://img.shields.io/badge/rust-1.100%20stable-orange)
![Dependencies](https://img.shields.io/badge/kernel%20dependencies-0-brightgreen)
![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)

[Türkçe README](README.tr.md) · [Architecture](docs/ARCHITECTURE.md) · [Threat model](docs/THREAT_MODEL.md) · [System calls](docs/SYSCALLS.md) · [Building](docs/BUILDING.md)

</div>

---

Kalkan is a small microkernel built around one idea: **nothing is trusted that can
be checked instead.** User programs hold no ambient authority — every kernel object
is reached through an unforgeable *capability* whose rights can only ever shrink.
The kernel verifies its own hardware protections at boot, verifies every program it
loads, and ships with an adversarial test suite in which an untrusted process tries
to break out of its sandbox on every CI run.

```text
Security posture:
  [PASS] NX (no-execute pages)                  EFER.NXE
  [PASS] SMEP (no kernel exec of user pages)    CR4.SMEP
  [PASS] SMAP (no kernel access to user pages)  CR4.SMAP, never lifted
  [PASS] UMIP (hide descriptor tables)          CR4.UMIP
  [PASS] RDTSC restricted to kernel             CR4.TSD
  [PASS] x87/SSE/AVX disabled for user space    no SIMD state to leak
  [PASS] W^X kernel image                       .text R-X, .rodata R--, .data RW-
  [PASS] Direct map non-executable              physmap is RW-, NX
  [PASS] Kernel stack guard pages               unmapped page below and above
  [PASS] KASLR (kernel image)                   slide 0x6e294000
  [PASS] Randomised stack/heap/MMIO placement   PML4 slots [318, 271, 494]
Boot module integrity (BLAKE2b-512):
  [PASS] init      161744 bytes  b0323fd9e0fb0f05...
  [PASS] sandbox   128848 bytes  5c322bdef14729e5...
...
[sandbox]   [BLOCKED] add GRANT to its console capability (EPERM)
[sandbox]   [BLOCKED] forge a different badge (identity spoofing) (EINVAL)
[sandbox]   [BLOCKED] smuggle a non-grantable capability over IPC (transfer refused by the kernel)
[sandbox]   [BLOCKED] make the kernel read kernel memory for us (EFAULT)
[sandbox]   [INFO] terminal escape injection attempt follows: ?[2J?[31mFAKE KERNEL LOG?[0m
[sandbox]   reading kernel memory at 0xffffffff80000000 ...
[fault] thread 'sandbox' killed: page fault (vector 14) at rip=0x96bcff8210 addr=0xffffffff80000000 err=0x4
[init]   [PASS] sandbox killed on its kernel memory access (page fault at 0xffffffff80000000)
[init] KALKAN-TEST: PASS - all 62 security tests passed
[kernel] system shut down cleanly
```

## Highlights

| | |
|---|---|
| 🔑 **Capabilities, no ambient authority** | seL4-style capability spaces, monotonic rights, unforgeable badges, a derivation tree with complete revocation, GRANT-based confinement. |
| 🦀 **Memory-safe by construction** | Rust, stable toolchain only. `unsafe` is *denied by the compiler* outside four low-level modules, and every `unsafe` block carries a `SAFETY:` justification (enforced by Clippy). |
| 🧪 **Policy you can test** | All access-control decisions live in [`kcore`](kcore/src/lib.rs): `#![forbid(unsafe_code)]`, zero dependencies, unit-tested and property-tested on the host, fuzzed in CI. |
| 🧱 **Hardware hardening, verified at boot** | NX, SMEP, SMAP (never lifted), UMIP, CR0.WP, CR4.TSD, no user SIMD, W^X everywhere, non-executable physmap, guard pages, KASLR — and the kernel *checks* each one by inspecting its own control registers and page tables. Fail-closed if a mandatory protection is missing. |
| 🔗 **Verified boot chain** | Pinned bootloader (tag + commit + BLAKE2b). The bootloader verifies kernel and modules; the kernel verifies modules **again** against digests compiled into it. Tampering is tested in CI. |
| ⚔️ **Adversarial test suite** | 62 boot-time security tests, including an untrusted process that actively attacks the kernel, plus a tamper test of the boot partition. |
| 📦 **Zero-dependency kernel** | No third-party crates in the kernel or its policy core; the supply chain is the Rust toolchain and one pinned bootloader binary. |

### By the numbers

| Component | Lines of Rust* | `unsafe` |
|---|---:|---|
| `kcore` — policy core | ~2 200 (incl. tests) | **forbidden** |
| `kernel/src/kernel` — objects, IPC, syscalls, loader | ~1 200 | **denied** |
| `kernel/src/arch` + `boot.rs` + `sync.rs` | ~1 400 | allowed, every block justified |
| `kernel/src/mm` — memory management | ~900 | allowed, every block justified |
| Third-party crates in the kernel | 0 | — |

<sub>*non-blank, non-comment lines</sub>

## Architecture

```mermaid
flowchart TB
    subgraph user["User space (CPL 3) — each process: own address space + own CSpace"]
        init["init<br/>root task + test suite"]
        sandbox["sandbox<br/>untrusted, 4 capabilities"]
    end
    subgraph kernel["Kalkan kernel (CPL 0)"]
        direction TB
        sys["System call + trap entry<br/>(register scrubbing, iretq only)"]
        policy["kcore — capability DB, rights, ELF validation, crypto<br/>forbid(unsafe_code) · host-tested · fuzzed"]
        objs["Objects: Thread · Endpoint · VSpace · Frame · Untyped"]
        mm["Memory: W^X page tables · zeroing frame allocator · hardened heap"]
        arch["arch: GDT/IDT/TSS · SMEP/SMAP/UMIP · APIC"]
    end
    limine["Limine (pinned) — verifies BLAKE2b of kernel and modules"]
    sandbox -- "IPC (badged, capability transfer needs GRANT)" --> init
    init --> sys
    sandbox --> sys
    sys --> policy --> objs --> mm --> arch
    limine --> kernel
```

* **Microkernel.** The kernel provides only address spaces, threads, IPC, memory
  objects and capabilities. Everything else belongs in user space.
* **Event-driven, single kernel stack.** Every trap is handled to completion with
  interrupts disabled; the kernel never blocks or sleeps. No kernel threads, no
  kernel-mode preemption, no lock juggling.
* **Rendezvous IPC** with `send` / `recv` / `call` / `reply`, kernel-assigned
  badges, optional capability transfer and kernel-generated fault messages.

Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Security model in one table

| Threat | Mitigation | Where |
|---|---|---|
| Privilege escalation via forged references | Capabilities are kernel objects addressed by slot; ids are generational | `kcore/src/cspace.rs`, `kcore/src/arena.rs` |
| Rights escalation | Derivation can only remove rights (exhaustively tested) | `kcore/src/rights.rs` |
| Capability leakage | Cross-CSpace transfer requires GRANT; revocation removes all descendants *and their mappings* | `kcore/src/cspace.rs`, `kernel/src/kernel/mod.rs` |
| Identity spoofing over IPC | Badges are set once by the minter and delivered by the kernel | `kernel/src/kernel/ipc.rs` |
| Kernel pointer passed to a syscall | The kernel never dereferences user pointers: it walks the target page tables and copies through the direct map | `kernel/src/mm/user.rs` |
| ret2usr / user data abuse | SMEP + SMAP, never lifted (no `stac` in the kernel) | `kernel/src/arch/x86_64/cpu.rs` |
| Code injection | W^X for kernel image, physmap, heap, stacks and user programs; W+X mappings are unrepresentable, and W^X holds per *frame* across aliases; the physmap alias of the kernel image is read-only | `kernel/src/mm/*`, `kcore/src/elf.rs` |
| Malformed executables | Strict, panic-free ELF validator (fuzzed); no interpreter, TLS, text relocations or dynamic linking | `kcore/src/elf.rs` |
| Address disclosure | KASLR, randomised physmap, randomised kernel stack/heap/MMIO slots, user ASLR, UMIP | `kernel/src/mm/kspace.rs`, `kernel/src/kernel/loader.rs` |
| Spectre v1 | Branch-free index clamping on syscall numbers and capability slots | `kcore/src/nospec.rs` |
| Spectre v2 / MDS / SWAPGS | IBRS + STIBP always on, IBPB on address-space switch, VERW on return (when supported), `lfence` after `swapgs` | `kernel/src/arch/x86_64/` |
| Speculative gadgets via stale registers | All GPRs zeroed on kernel entry | `kernel/src/arch/x86_64/entry.rs` |
| SYSRET privilege escalation (CVE-2012-0217) | Kernel always returns with `iretq`; RFLAGS/CS/SS sanitised | `kernel/src/arch/x86_64/entry.rs` |
| SIMD state leakage (LazyFP) | x87/SSE/AVX disabled for user space | `kernel/src/arch/x86_64/cpu.rs` |
| Cache-timing attacks | `rdtsc` restricted to ring 0 | `kernel/src/arch/x86_64/cpu.rs` |
| Information leaks via memory reuse | Frames zeroed on allocation *and* free; heap blocks zeroed; bootloader memory zeroed on reclaim | `kernel/src/mm/frame.rs`, `kernel/src/mm/heap.rs` |
| Heap corruption | Encoded (safe-linked) free lists, poisoning, double-free detection, guard pages — corruption panics | `kernel/src/mm/heap.rs` |
| Kernel stack overflow | Guard pages + IST stacks for #DF/NMI/#MC; stack probes | `kernel/src/mm/kspace.rs` |
| Resource exhaustion | Untyped memory budgets with refunds and revocation; per-address-space page-table quota with reclamation; a frame reserve user space can never touch; hard limits on every kernel table | `kernel/src/kernel/mod.rs` |
| Integer overflow | `overflow-checks = true` in release builds; checked arithmetic on all untrusted input | `Cargo.toml` |
| Terminal injection | User console output is sanitised (no ESC / control characters) | `kernel/src/log.rs` |
| Boot-time tampering | Pinned bootloader; BLAKE2b verification by bootloader *and* kernel | `xtask/`, `kernel/src/main.rs` |
| Supply chain | Zero kernel dependencies, `cargo-deny`, CI actions pinned by commit SHA | `deny.toml`, `.github/workflows/ci.yml` |

What is **not** covered yet is just as important — see the
[threat model](docs/THREAT_MODEL.md#known-limitations).

## Quick start

You need Rust (via [rustup](https://rustup.rs)), QEMU and git. The pinned
toolchain from `rust-toolchain.toml` is installed automatically.

```sh
# Windows (PowerShell): winget install Rustlang.Rustup; winget install SoftwareFreedomConservancy.QEMU
# Ubuntu/Debian:        sudo apt install qemu-system-x86 ovmf
# macOS:                brew install qemu

cargo xtask run      # build everything and boot Kalkan in QEMU
cargo xtask test     # security suite + boot tamper test (what CI runs)
cargo test -p kalkan-core   # host unit/property tests of the policy core
```

On Windows without Visual Studio, use the GNU host toolchain:
`rustup set default-host x86_64-pc-windows-gnu`. See [docs/BUILDING.md](docs/BUILDING.md).

## Repository layout

```text
kcore/            policy core: capabilities, rights, ELF validator, crypto (no unsafe, no deps)
kernel/
  src/arch/       x86-64: entry stubs, GDT/IDT/TSS, CPU hardening, APIC, entropy
  src/mm/         frame allocator, page tables, kernel address space, heap, user memory
  src/kernel/     objects, scheduler, IPC, system calls, program loader (no unsafe)
  src/boot.rs     Limine protocol (no third-party crate)
  src/posture.rs  boot-time security self check
user/
  libkalkan/      system call library
  init/           root task and the adversarial test suite
  sandbox/        untrusted process that tries to escape
xtask/            build, run and test orchestration (cargo xtask)
fuzz/             cargo-fuzz targets
docs/             architecture, threat model, system calls, building
```

## Testing

| Layer | How | Command |
|---|---|---|
| Policy core | Unit tests, exhaustive rights tests, randomised model checks, RFC test vectors (ChaCha20, BLAKE2b) | `cargo test -p kalkan-core` |
| Parsers | Truncation + 20 000 random mutations in unit tests; libFuzzer in CI | `cargo +nightly fuzz run elf` |
| Whole system | Boots in QEMU; 62 security tests incl. an attacking process | `cargo xtask test` |
| Boot integrity | Flips one byte of a module and strips its bootloader hash — the kernel must refuse it | `cargo xtask test` |
| Code quality | `rustfmt`, Clippy with `-D warnings`, `undocumented_unsafe_blocks = deny` | CI |

## Roadmap

- [ ] SMP support (per-CPU kernel stacks, IPIs, TLB shootdown)
- [ ] User-space process creation (Thread/VSpace retype) and a user-level ELF loader
- [ ] IOMMU (VT-d/AMD-Vi) to confine DMA, user-space drivers via IRQ capabilities
- [ ] Eager XSAVE so user space can use SIMD safely
- [ ] KPTI for Meltdown-affected CPUs, CET shadow stacks, kernel CFI
- [ ] Notification objects, timeouts, priorities
- [ ] Formal specification of the capability model

## Disclaimer

Kalkan is an educational and research project. It has not been formally verified
or independently audited and must not be relied on to protect real data. Please
report security issues as described in [SECURITY.md](SECURITY.md).

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
