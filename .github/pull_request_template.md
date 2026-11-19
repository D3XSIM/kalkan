## What and why

<!-- What does this change, and why? Link the issue it addresses. -->

## How it is tested

<!-- Which tests show that it works — and that misuse is refused? -->

## Checklist

- [ ] `cargo fmt --all` and the Clippy commands from [CONTRIBUTING.md](../CONTRIBUTING.md) pass
- [ ] `cargo test -p kalkan-core -p xtask` and `cargo xtask test` pass
- [ ] No new `unsafe` outside `arch`, `boot`, `mm` and `sync`; every `unsafe` block has a `// SAFETY:` comment
- [ ] New kernel state is covered by the self-audit (`kernel/src/kernel/audit.rs`)
- [ ] Docs updated (`docs/`, README) if behaviour or the ABI changed
- [ ] If you used AI tools, say so here (it is fine — the project was built with them — but reviewers should know)
