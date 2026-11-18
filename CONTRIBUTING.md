# Contributing to Kalkan

Thanks for your interest! Kalkan values correctness and security over features, so
contributions are held to a few strict rules.

## Ground rules

1. **No new `unsafe` outside `arch`, `boot`, `mm` and `sync`.** The kernel crate is
   `#![deny(unsafe_code)]`; only those modules opt out. `kcore` is
   `#![forbid(unsafe_code)]` and must stay that way.
2. **Every `unsafe` block has a `// SAFETY:` comment** explaining why the
   operation is sound (enforced by `clippy::undocumented_unsafe_blocks`).
3. **Policy belongs in `kcore`.** If a change decides *whether* something is
   allowed, the decision should live in `kcore` where it can be unit tested and
   fuzzed; the kernel only enforces it.
4. **No new dependencies** in `kcore`, `kernel` or `user/` without discussion. The
   kernel's supply chain is intentionally the Rust toolchain plus one pinned
   bootloader binary.
5. **Fail closed.** When an invariant is violated, refuse or stop — never continue
   in a possibly corrupted state. User-triggerable conditions must return an error,
   never panic.
6. **Test the attack, not just the feature.** New system calls or object types come
   with tests in `user/init` (and, where it makes sense, in `user/sandbox`) that show
   misuse is refused, and every new piece of derived kernel state is covered by
   the self-audit in `kernel/src/kernel/audit.rs`. See [docs/TESTING.md](docs/TESTING.md).

## Before opening a pull request

```sh
cargo fmt --all
cargo clippy -p kalkan-core -p xtask --all-targets -- -D warnings
cargo clippy -p kalkan-kernel --target x86_64-unknown-none -- -D warnings
cargo clippy -p libkalkan -p kalkan-init -p kalkan-sandbox --target x86_64-unknown-none -- -D warnings
cargo test -p kalkan-core -p xtask
cargo test -p kalkan-core --release -- --ignored
cargo xtask test
```

All of these run in CI.

## Reporting security issues

Please follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
