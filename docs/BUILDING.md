# Building and running Kalkan

## Requirements

* [rustup](https://rustup.rs). The exact toolchain (stable 1.100.0, with the
  `x86_64-unknown-none` target, `rustfmt` and `clippy`) is pinned in
  `rust-toolchain.toml` and installed automatically on first use.
* QEMU (`qemu-system-x86_64`) with UEFI firmware (OVMF / edk2).
* git (used once to fetch the pinned Limine release).

No C compiler, assembler, `make` or `xorriso` is needed.

### Windows

```powershell
winget install Rustlang.Rustup
winget install SoftwareFreedomConservancy.QEMU   # ships edk2 firmware in C:\Program Files\qemu\share
```

Without Visual Studio Build Tools, use the self-contained GNU host toolchain:

```powershell
rustup set default-host x86_64-pc-windows-gnu
```

### Linux (Debian/Ubuntu)

```sh
sudo apt install qemu-system-x86 ovmf git
```

### macOS

```sh
brew install qemu git
```

## Commands

| Command | What it does |
|---|---|
| `cargo xtask build` | Builds user programs, validates them, builds a normal kernel with their digests, fetches and verifies Limine, assembles `target/esp/` |
| `cargo xtask run` | Like `build`, but a *test kernel* (feature `selftest`), booted in QEMU with the serial console on your terminal |
| `cargo xtask check` | Static checks: no third-party packages, `unsafe` confinement, forbidden instructions, CI pinning, docs vs ABI |
| `cargo xtask test` | Static checks, then a normal kernel and a test kernel (features `qemu-exit`, `audit`, `selftest`) and every QEMU scenario: the suite on three machine sizes and in both local APIC modes, the normal kernel, randomisation, fail-closed CPUs, boot tampering (~2.5 min) |
| `cargo xtask test --quick` | The suite on the default machine and one tamper test (~1 min) |
| `cargo xtask dist` | The demo package of the release page: a test kernel plus run scripts for Windows, Linux and macOS, in `target/dist/` |
| `cargo xtask build --debug` / `run --debug` | Same with a debug kernel |
| `cargo test -p kalkan-core -p xtask` | Host tests of the policy core and the build tool |
| `cargo test -p kalkan-core --release -- --ignored` | Stress tests (millions of model steps and mutations) |
| `cargo +nightly fuzz run elf` (in `fuzz/`) | Fuzz the ELF validator (needs `cargo install cargo-fuzz`) |

Serial logs of every boot are written to `target/kalkan-*.log`. How the tests
work is described in [TESTING.md](TESTING.md).

## Environment variables

| Variable | Purpose |
|---|---|
| `KALKAN_QEMU` | Path to `qemu-system-x86_64` |
| `KALKAN_OVMF` | Path to the OVMF/edk2 *code* firmware image |
| `KALKAN_OVMF_VARS` | Optional variable store template |

## How the boot partition is built

```text
target/esp/
├── EFI/BOOT/BOOTX64.EFI          Limine (tag v11.2.1-binary, commit + BLAKE2b pinned)
└── boot/
    ├── kalkan                    kernel (PIE, relocated by Limine → KASLR)
    ├── init, sandbox             user programs (PIE, relocated by the kernel → ASLR)
    └── limine/limine.conf        every path carries #<BLAKE2b-512>
```

QEMU exposes the directory as a FAT disk (`-drive file=fat:rw:esp`). To boot real
hardware, copy the contents of `target/esp/` to a FAT32-formatted USB stick and
boot it in UEFI mode. The kernel refuses to start on CPUs without NX, SMEP and
SMAP.

## Troubleshooting

* **`linker 'x86_64-w64-mingw32-gcc' not found` / `link.exe not found`** — set the
  default host as described above, or install Visual Studio Build Tools.
* **`PANIC: High memory allocator: Out of memory`** — printed by the bootloader, not
  the kernel: the virtual machine needs at least 128 MiB of RAM for the firmware
  and Limine.
* **`UEFI firmware (OVMF) not found`** — install `ovmf`, or set `KALKAN_OVMF`.
* **`no reference digest ... compiled in`** — the kernel was built without
  `cargo xtask`; it refuses to run unverified modules by design.
