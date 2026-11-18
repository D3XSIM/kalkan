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
| `cargo xtask build` | Builds user programs, validates them, builds the kernel with their digests, fetches and verifies Limine, assembles `target/esp/` |
| `cargo xtask run` | `build` + boots in QEMU with the serial console on your terminal |
| `cargo xtask test` | Release build with the `qemu-exit` feature, runs the security suite headless, then the tamper test |
| `cargo xtask build --debug` / `run --debug` | Same with a debug kernel |
| `cargo test -p kalkan-core` | Host tests of the policy core |
| `cargo +nightly fuzz run elf` (in `fuzz/`) | Fuzz the ELF validator (needs `cargo install cargo-fuzz`) |

Logs of test runs are written to `target/kalkan-test.log` and
`target/kalkan-tamper.log`.

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
* **`UEFI firmware (OVMF) not found`** — install `ovmf`, or set `KALKAN_OVMF`.
* **`no reference digest ... compiled in`** — the kernel was built without
  `cargo xtask`; it refuses to run unverified modules by design.
