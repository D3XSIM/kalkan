//! `cargo xtask dist`: a package anyone can run without installing Rust.
//!
//! It holds the boot partition of a *test kernel* — exactly the configuration
//! that `cargo xtask test` checks — and scripts that boot it in QEMU, so the
//! adversarial suite can be watched in about half a minute.

use std::fs;
use std::path::{Path, PathBuf};

use crate::{Result, digest_hex, read, step, target_dir, write};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Packs the boot partition `esp` and the run scripts into
/// `target/dist/kalkan-demo-v<version>.zip`.
pub fn package(esp: &Path) -> Result<PathBuf> {
    step("packaging the demo");
    let base = format!("kalkan-demo-v{VERSION}");
    let mut files = Vec::new();
    collect(esp, esp, &mut files)?;
    files.sort();

    let mut zip = Zip::default();
    let readme = README.replace("{VERSION}", VERSION);
    zip.add(&format!("{base}/README.txt"), readme.as_bytes(), false);
    // Batch files are safest with CRLF line endings.
    zip.add(
        &format!("{base}/run.cmd"),
        RUN_CMD.replace('\n', "\r\n").as_bytes(),
        false,
    );
    zip.add(&format!("{base}/run.ps1"), RUN_PS1.as_bytes(), false);
    zip.add(&format!("{base}/run.sh"), RUN_SH.as_bytes(), true);
    for rel in &files {
        zip.add(&format!("{base}/esp/{rel}"), &read(&esp.join(rel))?, false);
    }

    let bytes = zip.finish();
    let out = target_dir().join("dist").join(format!("{base}.zip"));
    write(&out, &bytes)?;
    println!(
        "    {} ({} KiB, {} files, blake2b {}...)",
        out.display(),
        bytes.len() / 1024,
        files.len() + 4,
        &digest_hex(&bytes)[..16]
    );
    Ok(out)
}

/// Relative paths (separated by `/`) of every file below `dir`.
fn collect(root: &Path, dir: &Path, out: &mut Vec<String>) -> Result<()> {
    for entry in fs::read_dir(dir).map_err(|e| format!("reading {}: {e}", dir.display()))? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.is_dir() {
            collect(root, &path, out)?;
        } else {
            let rel = path.strip_prefix(root).map_err(|e| e.to_string())?;
            out.push(rel.to_string_lossy().replace('\\', "/"));
        }
    }
    Ok(())
}

/// A minimal ZIP writer: stored (uncompressed) entries only. Enough for a small
/// package, and it keeps the project free of third-party code.
#[derive(Default)]
struct Zip {
    data: Vec<u8>,
    central: Vec<u8>,
    entries: u16,
}

/// 1980-01-01 in MS-DOS date format: fixed, so the package is reproducible.
const DOS_DATE: u16 = (1 << 5) | 1;

impl Zip {
    fn add(&mut self, name: &str, contents: &[u8], executable: bool) {
        let crc = crc32(contents);
        let size = contents.len() as u32;
        let offset = self.data.len() as u32;
        let name_len = name.len() as u16;

        // Local file header: version needed, flags, method (stored), time, date.
        put32(&mut self.data, 0x0403_4b50);
        for v in [20, 0, 0, 0, DOS_DATE] {
            put16(&mut self.data, v);
        }
        for v in [crc, size, size] {
            put32(&mut self.data, v);
        }
        put16(&mut self.data, name_len);
        put16(&mut self.data, 0);
        self.data.extend_from_slice(name.as_bytes());
        self.data.extend_from_slice(contents);

        // Central directory entry, "made by" Unix so that the file mode counts.
        let mode: u32 = if executable { 0o100_755 } else { 0o100_644 };
        put32(&mut self.central, 0x0201_4b50);
        for v in [(3 << 8) | 20, 20, 0, 0, 0, DOS_DATE] {
            put16(&mut self.central, v);
        }
        for v in [crc, size, size] {
            put32(&mut self.central, v);
        }
        // Name length, extra field, comment, disk number, internal attributes.
        for v in [name_len, 0, 0, 0, 0] {
            put16(&mut self.central, v);
        }
        put32(&mut self.central, mode << 16);
        put32(&mut self.central, offset);
        self.central.extend_from_slice(name.as_bytes());
        self.entries += 1;
    }

    fn finish(mut self) -> Vec<u8> {
        let (size, offset) = (self.central.len() as u32, self.data.len() as u32);
        self.data.append(&mut self.central);
        put32(&mut self.data, 0x0605_4b50);
        for v in [0, 0, self.entries, self.entries] {
            put16(&mut self.data, v);
        }
        put32(&mut self.data, size);
        put32(&mut self.data, offset);
        put16(&mut self.data, 0);
        self.data
    }
}

fn put16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// CRC-32 (IEEE 802.3), as ZIP requires.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & (crc & 1).wrapping_neg());
        }
    }
    !crc
}

const README: &str = "\
Kalkan v{VERSION} - demo package
================================

Kalkan is a capability-based, security-first microkernel for x86-64, written in
Rust: https://github.com/D3XSIM/kalkan

This package boots a *test kernel* in QEMU and runs the adversarial security
suite: untrusted processes attack the kernel from every angle, and the kernel
must stop every attack, audit its own state after every trap and get every
resource back. It takes about half a minute; the output appears in the window.

Requirements: QEMU for x86-64 with UEFI firmware (OVMF)
  Windows        winget install SoftwareFreedomConservancy.QEMU
  Debian/Ubuntu  sudo apt install qemu-system-x86 ovmf
  Fedora         sudo dnf install qemu-system-x86 edk2-ovmf
  macOS          brew install qemu

Run
  Windows        double-click run.cmd
                 (or: powershell -ExecutionPolicy Bypass -File run.ps1)
  Linux, macOS   ./run.sh

What is inside
  esp/                         the boot partition: the Limine bootloader
                               (pinned version), the kernel, and the user
                               programs init (the test suite) and sandbox
                               (the attacker)
  esp/boot/limine/limine.conf  the BLAKE2b-512 digest of every file the
                               bootloader loads; it refuses anything that
                               differs, and the kernel checks the user
                               programs again against digests built into it

A test kernel is for testing only: it reveals its memory layout to the test
suite and prints addresses in its log. Build a normal kernel from source with
`cargo xtask build` (see the repository's docs/BUILDING.md).
";

const RUN_CMD: &str = "\
@echo off
rem Boots the Kalkan demo in QEMU. Double-click this file.
powershell -NoProfile -ExecutionPolicy Bypass -File \"%~dp0run.ps1\"
echo.
pause
";

const RUN_PS1: &str = r##"# Boots the Kalkan demo in QEMU on Windows (run.cmd starts this script).
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$qemu = (Get-Command qemu-system-x86_64.exe -ErrorAction SilentlyContinue).Source
if (-not $qemu) { $qemu = Join-Path $env:ProgramFiles 'qemu\qemu-system-x86_64.exe' }
if (-not (Test-Path -LiteralPath $qemu)) {
    Write-Host 'QEMU was not found. Install it with:  winget install SoftwareFreedomConservancy.QEMU'
    exit 1
}
$share = Join-Path (Split-Path -Parent $qemu) 'share'
$code = Join-Path $share 'edk2-x86_64-code.fd'
$vars = Join-Path $share 'edk2-i386-vars.fd'
if (-not (Test-Path -LiteralPath $code)) {
    Write-Host "UEFI firmware was not found: $code"
    exit 1
}
$qemuArgs = @(
    '-machine', 'q35', '-cpu', 'max', '-m', '256M', '-smp', '1',
    '-no-reboot', '-serial', 'stdio', '-display', 'none', '-monitor', 'none',
    '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04',
    '-drive', "if=pflash,format=raw,readonly=on,file=$code"
)
if (Test-Path -LiteralPath $vars) {
    Copy-Item -LiteralPath $vars -Destination 'ovmf-vars.fd' -Force
    $qemuArgs += @('-drive', 'if=pflash,format=raw,file=ovmf-vars.fd')
}
$qemuArgs += @('-drive', 'format=raw,file=fat:rw:esp')
& $qemu @qemuArgs
if ($LASTEXITCODE -eq 33) {
    Write-Host "`nKalkan shut down cleanly."
} else {
    Write-Host "`nQEMU exited with code $LASTEXITCODE."
}
"##;

const RUN_SH: &str = r##"#!/bin/sh
# Boots the Kalkan demo in QEMU on Linux or macOS.
set -eu
cd "$(dirname "$0")"
QEMU=${KALKAN_QEMU:-qemu-system-x86_64}
if ! command -v "$QEMU" >/dev/null 2>&1; then
    echo "QEMU was not found. Debian/Ubuntu: sudo apt install qemu-system-x86 ovmf" >&2
    echo "Fedora: sudo dnf install qemu-system-x86 edk2-ovmf   macOS: brew install qemu" >&2
    exit 1
fi
CODE=${KALKAN_OVMF:-}
VARS=${KALKAN_OVMF_VARS:-}
if [ -z "$CODE" ]; then
    SHARE=$(dirname "$(command -v "$QEMU")")/../share/qemu
    for pair in \
        "$SHARE/edk2-x86_64-code.fd $SHARE/edk2-i386-vars.fd" \
        "/usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/OVMF/OVMF_VARS_4M.fd" \
        "/usr/share/OVMF/OVMF_CODE.fd /usr/share/OVMF/OVMF_VARS.fd" \
        "/usr/share/edk2/ovmf/OVMF_CODE.fd /usr/share/edk2/ovmf/OVMF_VARS.fd" \
        "/usr/share/edk2/x64/OVMF_CODE.4m.fd /usr/share/edk2/x64/OVMF_VARS.4m.fd" \
        "/usr/share/edk2/x64/OVMF_CODE.fd /usr/share/edk2/x64/OVMF_VARS.fd" \
        "/usr/share/qemu/edk2-x86_64-code.fd /usr/share/qemu/edk2-i386-vars.fd" \
        "/opt/homebrew/share/qemu/edk2-x86_64-code.fd /opt/homebrew/share/qemu/edk2-i386-vars.fd" \
        "/usr/local/share/qemu/edk2-x86_64-code.fd /usr/local/share/qemu/edk2-i386-vars.fd"
    do
        set -- $pair
        if [ -f "$1" ]; then
            CODE=$1
            VARS=$2
            break
        fi
    done
fi
if [ -z "$CODE" ] || [ ! -f "$CODE" ]; then
    echo "UEFI firmware (OVMF) was not found; install it or set KALKAN_OVMF" >&2
    exit 1
fi
set -- -machine q35 -cpu max -m 256M -smp 1 -no-reboot -serial stdio -display none \
    -monitor none -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    -drive "if=pflash,format=raw,readonly=on,file=$CODE"
if [ -n "$VARS" ] && [ -f "$VARS" ]; then
    cp "$VARS" ovmf-vars.fd
    chmod u+w ovmf-vars.fd
    set -- "$@" -drive if=pflash,format=raw,file=ovmf-vars.fd
fi
set +e
"$QEMU" "$@" -drive format=raw,file=fat:rw:esp
status=$?
echo
if [ "$status" -eq 33 ]; then
    echo "Kalkan shut down cleanly."
else
    echo "QEMU exited with code $status."
fi
"##;

#[cfg(test)]
mod tests {
    use super::{Zip, crc32};

    #[test]
    fn crc32_matches_the_standard_check_value() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn zip_has_local_entry_central_directory_and_end_record() {
        let mut zip = Zip::default();
        zip.add("a/b.txt", b"hello", false);
        let bytes = zip.finish();
        assert_eq!(bytes.len(), (30 + 7 + 5) + (46 + 7) + 22);
        assert_eq!(&bytes[..4], b"PK\x03\x04");
        assert_eq!(&bytes[42..46], b"PK\x01\x02");
        assert_eq!(&bytes[bytes.len() - 22..][..4], b"PK\x05\x06");
    }
}
