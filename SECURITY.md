# Security Policy

Kalkan is a security-focused research kernel, so security reports are the most
valuable contributions it can get.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Use GitHub's private vulnerability reporting: *Security* tab → *Report a
vulnerability*. Include:

* the commit you tested,
* the affected component (e.g. `kernel/src/kernel/syscall.rs`),
* a description of the impact (what an attacker gains, from which starting point),
* a proof of concept if possible — ideally a modified `user/sandbox` program that
  demonstrates the issue under `cargo xtask test`.

You can expect an acknowledgement within 7 days. Confirmed issues are fixed in the
open after a fix is ready, with credit to the reporter unless anonymity is requested.

## Scope

In scope — anything that lets an **unprivileged user process** (such as
`user/sandbox`, holding only the capabilities it was granted):

* execute code in or read/write memory of the kernel or another process;
* obtain, forge, keep after revocation, or escalate the rights of a capability;
* impersonate another process (forge a badge);
* make the kernel panic, hang, or leak memory (denial of service);
* learn kernel addresses or other secrets (information disclosure);
* bypass the boot integrity checks.

Also in scope: bugs in the policy core (`kcore`), the ELF validator, the boot
chain (`xtask`, `limine.conf` generation) and the CI supply-chain configuration.

Out of scope: attacks that require physical access, DMA from malicious devices,
or hardware side channels listed under *Known limitations* in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — unless you show a practical way to
mitigate them.

## Supported versions

Only the latest commit on the default branch is supported.
