//! Booting the assembled boot partition in QEMU.

use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use crate::{Result, step, target_dir, write};

/// QEMU exit status for `outl(0xf4, 0x10)`: `(0x10 << 1) | 1` — clean shutdown.
pub const EXIT_SUCCESS: i32 = 33;
/// QEMU exit status for `outl(0xf4, 0x11)` — the kernel stopped with an error.
pub const EXIT_FAILURE: i32 = 35;

/// The virtual machine a boot runs on.
#[derive(Clone, Copy, Debug)]
pub struct Machine<'a> {
    pub memory: &'a str,
    pub cpu: &'a str,
}

impl Default for Machine<'_> {
    fn default() -> Self {
        Self {
            memory: "256M",
            cpu: "max",
        }
    }
}

fn find_qemu() -> Result<PathBuf> {
    if let Ok(p) = env::var("KALKAN_QEMU") {
        return Ok(PathBuf::from(p));
    }
    let exe = if cfg!(windows) {
        "qemu-system-x86_64.exe"
    } else {
        "qemu-system-x86_64"
    };
    if let Some(paths) = env::var_os("PATH") {
        for dir in env::split_paths(&paths) {
            let candidate = dir.join(exe);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    for dir in [
        r"C:\Program Files\qemu",
        "/opt/homebrew/bin",
        "/usr/local/bin",
    ] {
        let candidate = Path::new(dir).join(exe);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err("qemu-system-x86_64 not found (install QEMU or set KALKAN_QEMU)".into())
}

/// Locates UEFI firmware (code) and an optional variable store template.
fn find_ovmf(qemu: &Path) -> Result<(PathBuf, Option<PathBuf>)> {
    if let Ok(p) = env::var("KALKAN_OVMF") {
        return Ok((
            PathBuf::from(p),
            env::var("KALKAN_OVMF_VARS").ok().map(PathBuf::from),
        ));
    }
    let share = qemu.parent().map(|d| d.join("share")).unwrap_or_default();
    let pairs: [(PathBuf, PathBuf); 8] = [
        (
            share.join("edk2-x86_64-code.fd"),
            share.join("edk2-i386-vars.fd"),
        ),
        (
            "/usr/share/OVMF/OVMF_CODE_4M.fd".into(),
            "/usr/share/OVMF/OVMF_VARS_4M.fd".into(),
        ),
        (
            "/usr/share/OVMF/OVMF_CODE.fd".into(),
            "/usr/share/OVMF/OVMF_VARS.fd".into(),
        ),
        (
            "/usr/share/edk2/x64/OVMF_CODE.fd".into(),
            "/usr/share/edk2/x64/OVMF_VARS.fd".into(),
        ),
        (
            "/usr/share/edk2-ovmf/x64/OVMF_CODE.fd".into(),
            "/usr/share/edk2-ovmf/x64/OVMF_VARS.fd".into(),
        ),
        (
            "/usr/share/qemu/edk2-x86_64-code.fd".into(),
            "/usr/share/qemu/edk2-i386-vars.fd".into(),
        ),
        (
            "/opt/homebrew/share/qemu/edk2-x86_64-code.fd".into(),
            "/opt/homebrew/share/qemu/edk2-i386-vars.fd".into(),
        ),
        (
            "/usr/local/share/qemu/edk2-x86_64-code.fd".into(),
            "/usr/local/share/qemu/edk2-i386-vars.fd".into(),
        ),
    ];
    for (code, vars) in pairs {
        if code.is_file() {
            return Ok((code, vars.is_file().then_some(vars)));
        }
    }
    Err("UEFI firmware (OVMF) not found; set KALKAN_OVMF to an OVMF_CODE file".into())
}

/// Builds the QEMU command line for booting `esp` (a directory under `target/`).
fn command(esp: &Path, machine: &Machine<'_>) -> Result<Command> {
    let qemu = find_qemu()?;
    let (code, vars) = find_ovmf(&qemu)?;
    let target = target_dir();
    let esp_rel = esp
        .strip_prefix(&target)
        .map_err(|_| "ESP outside target dir")?;

    let mut cmd = Command::new(&qemu);
    cmd.current_dir(&target)
        .args([
            "-machine",
            "q35",
            "-cpu",
            machine.cpu,
            "-m",
            machine.memory,
            "-smp",
            "1",
        ])
        .args([
            "-no-reboot",
            "-serial",
            "stdio",
            "-display",
            "none",
            "-monitor",
            "none",
        ])
        .args(["-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"])
        .arg("-drive")
        .arg(format!(
            "if=pflash,format=raw,readonly=on,file={}",
            code.display()
        ));
    if let Some(vars) = vars {
        let local = target.join("ovmf-vars.fd");
        fs::copy(&vars, &local).map_err(|e| format!("copying OVMF vars: {e}"))?;
        cmd.args(["-drive", "if=pflash,format=raw,file=ovmf-vars.fd"]);
    }
    // A relative path avoids drive-letter colons, which the vvfat syntax cannot take.
    let esp_arg = esp_rel.to_string_lossy().replace('\\', "/");
    cmd.arg("-drive")
        .arg(format!("format=raw,file=fat:rw:{esp_arg}"));
    Ok(cmd)
}

/// Boots interactively with the serial console on stdout.
pub fn run_interactive(esp: &Path) -> Result<()> {
    step("booting in QEMU");
    let st = command(esp, &Machine::default())?
        .status()
        .map_err(|e| format!("starting QEMU: {e}"))?;
    match st.code() {
        Some(0 | EXIT_SUCCESS) => Ok(()),
        other => Err(format!("QEMU exited with {other:?}")),
    }
}

/// The outcome of a headless boot.
#[derive(Debug)]
pub struct Boot {
    /// QEMU's exit status (`None` if it had to be killed).
    pub exit: Option<i32>,
    /// The serial log, one entry per line, exactly as the guest printed it.
    pub raw: Vec<String>,
    /// The serial log with terminal escape sequences removed.
    pub log: Vec<String>,
    /// The time limit was reached.
    pub timed_out: bool,
}

impl Boot {
    /// `true` if any log line contains `needle`.
    pub fn has(&self, needle: &str) -> bool {
        self.log.iter().any(|l| l.contains(needle))
    }

    /// The text following `marker` up to the next delimiter, in the first line
    /// that contains `marker`.
    pub fn value_after(&self, marker: &str) -> Option<String> {
        self.log.iter().find_map(|l| {
            let rest = &l[l.find(marker)? + marker.len()..];
            let end = rest.find([' ', ',', ')', ';']).unwrap_or(rest.len());
            Some(rest[..end].to_string())
        })
    }
}

/// Removes ANSI escape sequences (`ESC [ ... letter`) and carriage returns.
fn strip_escapes(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\x1b' if chars.peek() == Some(&'[') => {
                chars.next();
                for c in chars.by_ref() {
                    if c.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            '\r' => {}
            _ => out.push(c),
        }
    }
    out
}

/// Boots headless with a time limit.
///
/// The log is saved to `target/<log_name>`. With `echo` the guest's output is
/// also printed. If a line contains `stop_on`, QEMU is stopped right away.
pub fn boot(
    esp: &Path,
    machine: &Machine<'_>,
    log_name: &str,
    timeout: Duration,
    echo: bool,
    stop_on: Option<&str>,
) -> Result<Boot> {
    let mut child = command(esp, machine)?
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .stdin(Stdio::null())
        .spawn()
        .map_err(|e| format!("starting QEMU: {e}"))?;
    let stdout = child.stdout.take().ok_or("no QEMU stdout")?;
    let (tx, rx) = mpsc::channel::<String>();
    thread::spawn(move || {
        for line in BufReader::new(stdout)
            .split(b'\n')
            .map_while(std::result::Result::ok)
        {
            if tx
                .send(String::from_utf8_lossy(&line).into_owned())
                .is_err()
            {
                break;
            }
        }
    });

    let deadline = Instant::now() + timeout;
    let mut boot = Boot {
        exit: None,
        raw: Vec::new(),
        log: Vec::new(),
        timed_out: false,
    };
    let mut stopped = false;
    loop {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(line) => {
                if echo {
                    let mut out = std::io::stdout().lock();
                    let _ = out.write_all(line.as_bytes());
                    let _ = out.write_all(b"\n");
                }
                let clean = strip_escapes(&line);
                stopped = stop_on.is_some_and(|needle| clean.contains(needle));
                boot.raw.push(line);
                boot.log.push(clean);
                if stopped {
                    break;
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        if Instant::now() > deadline {
            boot.timed_out = true;
            break;
        }
    }
    if boot.timed_out || stopped {
        let _ = child.kill();
        let _ = child.wait();
    } else {
        boot.exit = child.wait().map_err(|e| e.to_string())?.code();
    }
    let _ = write(&target_dir().join(log_name), boot.raw.join("\n").as_bytes());
    Ok(boot)
}
