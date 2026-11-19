# Changelog

## v0.2.0 — 2026-11-19

### Security fixes

* A server that called `ep_recv` again without replying, or that died while it
  owed a reply, left its caller blocked forever. The caller is now released
  with `EDEAD`, and the self-audit checks that every waiting caller is owed its
  reply by exactly one live thread.
* A dead process kept its memory until somebody received its fault report —
  forever, if nobody did. It now releases its capability space, address space
  and capabilities at once; a report that nobody can ever receive (its fault
  endpoint lost its last capability) is dropped.
* When a mapping failed and was rolled back, the page tables it had created were
  freed without invalidating the CPU's paging-structure caches.
* A handful of full capability spaces could exhaust the kernel's global
  capability table for every other process. The capability and endpoint tables
  are now sized so that no process can exhaust them for the others.
* The TSS pointed at the guarded interrupt stacks before the kernel had switched
  to the page tables that map them; an NMI in that window would have reset the
  machine.

### Added

* `thread_kill`: terminate a thread you hold a `WRITE` capability to.
* Randomness is a capability: `random` needs `READ` on the new entropy object.
* **Test kernels** (`selftest` feature): probe processes, the diagnostic system
  calls `kernel_stats` and `kernel_layout`, and addresses in the log exist only
  there. A normal kernel answers the diagnostics with `ENOSYS` and prints
  `<hidden>` instead of addresses.
* The local APIC runs in x2APIC mode whenever the CPU supports it.
* `cargo xtask dist`: a demo package that runs without Rust.

### Tests

* The kernel-memory attacks hit unmapped addresses under KASLR and therefore
  proved nothing. They now attack kernel code, data, stack, heap and the direct
  map at their real addresses and must fault with the page-present bit set.
* Six process life-cycle tests (abandoned calls, a server dying with a call,
  reports nobody collects or can ever collect, `thread_kill` on running and
  blocked processes); exact leak checks.
* The self-audit walks every user page table in the reverse direction.
* New scenarios: a normal kernel (no test facilities, no addresses in the log),
  the local APIC in x2APIC and in xAPIC mode, stricter randomisation and
  tampered-kernel checks. **143** checks on a test kernel, 75 on a normal one.

### ABI changes

* `random(entropy)` takes a capability; new `thread_kill` (18) and
  `kernel_layout` (20); `kernel_stats` moved from 18 to 19. See
  [docs/SYSCALLS.md](docs/SYSCALLS.md).

## v0.1.0 — 2026-11-18

First publication: the capability microkernel, the verified boot chain, the
adversarial test suite, and the first round of deep security testing (the
self-audit after every trap, one probe process per hardware attack, the system
call fuzzer, the boot scenarios).
