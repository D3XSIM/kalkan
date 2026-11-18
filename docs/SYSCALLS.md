# System call reference

Calling convention: `syscall` with the number in `rax` and arguments in `rdi`,
`rsi`, `rdx`, `r10`, `r8`, `r9`. The status is returned in `rax` (0 = success),
results in `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`. `rcx` and `r11` are clobbered.
Numbers and error codes are defined in [`kcore/src/abi.rs`](../kcore/src/abi.rs).

Every capability argument is a **slot index** in the caller's capability space.

| # | Name | Arguments | Required rights | Returns |
|---|---|---|---|---|
| 0 | `debug_write` | console, ptr, len (≤ 4096) | `WRITE` on a console cap | — |
| 1 | `cap_mint` | src, dst, rights, badge | rights ⊆ rights(src); badge only if src unbadged | — |
| 2 | `cap_delete` | slot | — | — |
| 3 | `cap_revoke` | slot | — | — |
| 4 | `cap_info` | slot | — | type, rights, badge |
| 5 | `untyped_retype` | untyped, type (`FRAME`/`ENDPOINT`), dst | `WRITE` on untyped | — (the new capability is a child of the untyped capability: revoking it destroys the object) |
| 6 | `vspace_map` | vspace, frame, vaddr, perms | `WRITE` on vspace; perms ⊆ rights(frame); never `W+X`, and never writable while the frame is executable elsewhere (or vice versa) | — |
| 7 | `vspace_unmap` | frame | — | — |
| 8 | `thread_grant` | thread, src, dst, rights, badge | `WRITE` on thread; `GRANT` on src | — |
| 9 | `thread_start` | thread | `WRITE` on thread | — |
| 10 | `thread_set_fault_ep` | thread, endpoint | `WRITE` on both | — |
| 11 | `thread_exit` | code | — | does not return |
| 12 | `yield` | — | — | — |
| 13 | `ep_send` | ep, m0, m1, m2, m3, cap | `WRITE` on ep (+`GRANT` on cap) | — |
| 14 | `ep_recv` | ep, recv_slot | `READ` on ep | badge, m0–m3, flags |
| 15 | `ep_call` | ep, m0, m1, m2, m3, cap | `WRITE` on ep (+`GRANT` on cap) | m0–m3 of the reply |
| 16 | `ep_reply` | m0, m1, m2, m3 | one-shot reply right | — |
| 17 | `random` | entropy | `READ` on an entropy cap | 64 bits from the kernel CSPRNG |
| 18 | `thread_kill` | thread | `WRITE` on thread | — (does not return if the caller kills itself) |
| 19 | `kernel_stats` | console | `READ` on a console cap; **test kernels only** | free frames, heap bytes, capabilities, threads, frame objects, endpoints (diagnostics for the leak tests) |
| 20 | `kernel_layout` | console | `READ` on a console cap; **test kernels only** | addresses of kernel code, kernel data, the kernel image in the direct map, the kernel stack and a kernel heap object (so the attacks of the test suite hit live kernel memory despite KASLR) |

*Test kernels* are built with the `selftest` feature (`cargo xtask run`/`test`).
Every other kernel answers `kernel_stats` and `kernel_layout` with `ENOSYS`,
creates no probe processes, and prints no addresses in its log.

`cap = u64::MAX` (`NO_CAP`) means "no capability". Slot 0 is the null slot: it is
always empty and is rejected as a destination (`EBADSLOT`).

## Thread life cycle

* A thread ends by `thread_exit`, by a fault, or by `thread_kill`. Its capability
  space, its address space (unless capabilities still refer to it) and every
  capability it held are released **at once**.
* After an exit or a fault, the kernel sends a report to the thread's fault
  endpoint (see the `FAULT` flag below). Until somebody receives it, only the
  thread's small kernel record remains. If no capability to that endpoint exists
  any more, nobody could ever receive the report: it is dropped and the record
  removed. `thread_kill` sends no report: whoever holds the thread capability
  decided the outcome.
* A thread that terminates while it owes a reply, or a server that calls
  `ep_recv` again without replying, releases the waiting caller with `EDEAD`. No
  thread waits forever for a reply that can no longer come.

## Errors

| Code | Name | Meaning |
|---|---|---|
| 1 | `EINVAL` | Malformed argument (unknown rights bits, bad object type, ...) |
| 2 | `EPERM` | Missing right, rights escalation, or transfer without `GRANT` |
| 3 | `EBADSLOT` | Slot index outside the capability space |
| 4 | `EEMPTY` | Slot is empty |
| 5 | `EEXIST` | Destination slot is occupied |
| 6 | `ETYPE` | Capability refers to the wrong kind of object |
| 7 | `ENOMEM` | Budget or kernel limit exhausted |
| 8 | `EFAULT` | Invalid user pointer or address (kernel half, unmapped, overflow) |
| 9 | `ENOSYS` | Unknown system call |
| 10 | `ESTATE` | Object in the wrong state (e.g. starting a running thread) |
| 11 | `EDEAD` | The object or peer was destroyed |
| 12 | `EMAPPED` | Address or frame capability already mapped |
| 13 | `EWX` | Writable + executable mapping requested |

A failing system call never changes kernel state. Rights are checked before the
object type, so a capability that is both of the wrong type and lacks the required
right yields `EPERM`.

## IPC message flags (`r9` after `ep_recv`)

| Bit | Name | Meaning |
|---|---|---|
| 0 | `CAP_TRANSFERRED` | A capability was placed in `recv_slot` |
| 1 | `CAP_REFUSED` | The sender attached a capability but the transfer was refused |
| 2 | `FAULT` | Kernel-generated report about a supervised thread: `[vector, error, address, rip]` for a fault, `[EXIT_VECTOR (0x100), exit code, 0, 0]` for a voluntary exit |

## Initial capabilities of the root task

| Slot | Object | Rights |
|---|---|---|
| 1 | own VSpace | `rwxg` |
| 2 | own thread | `rwxg` |
| 3 | untyped budget (128 KiB) | `rwxg` |
| 4 | debug console | `rw-g` |
| 5 | sandbox thread (not started) | `rwxg` |
| 6 | sandbox VSpace | `rwxg` |
| 7 | entropy (the kernel CSPRNG) | `r--g` |
| 64… | probe threads (test kernels only, `PROBE_COUNT` of them) | `rwxg` |
| 128… | probe VSpaces (test kernels only) | `rwxg` |
