//! Build orchestration for Kalkan.
//!
//! ```text
//! cargo xtask build [--debug]   build everything and assemble the boot partition
//! cargo xtask run   [--debug]   build and boot in QEMU (serial console on stdout)
//! cargo xtask test              build with `qemu-exit` and run the security suite
//! ```
//!
//! The build is a small chain of trust:
//!
//! 1. user programs are built and validated with the kernel's own ELF checker;
//! 2. their BLAKE2b-512 digests are compiled *into the kernel*, which refuses to run
//!    a module whose digest does not match;
//! 3. the digests of the kernel and of every module are also written into
//!    `limine.conf`, so the bootloader verifies them before loading;
//! 4. the Limine binary itself is pinned to a release tag, a git commit **and** a
//!    BLAKE2b-512 digest.

use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use kcore::{blake2b, elf, hex};

const TARGET: &str = "x86_64-unknown-none";
const LIMINE_URL: &str = "https://github.com/Limine-Bootloader/Limine.git";
const LIMINE_TAG: &str = "v11.2.1-binary";
const LIMINE_COMMIT: &str = "deba356b4a70ee183ec3214864f0ba2ffe510b8c";
const LIMINE_EFI_BLAKE2B: &str = "d71f8846f3a3c0368d64ae73758901ca647b69f834a83ccf67766503812c3515\
                                  646e56529275f980abbdfd83492944348343b96f9a338da757dea34263d626aa";
const TEST_TIMEOUT: Duration = Duration::from_secs(300);
/// QEMU exit status for `outl(0xf4, 0x10)`: (0x10 << 1) | 1.
const QEMU_SUCCESS: i32 = 33;

type Result<T> = std::result::Result<T, String>;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let debug = args.iter().any(|a| a == "--debug");
    let result = match args.first().map(String::as_str) {
        Some("build") => build(!debug, false).map(|_| ()),
        Some("run") => build(!debug, true).and_then(|esp| run(&esp)),
        Some("test") => build(true, true).and_then(|esp| test(&esp)),
        _ => {
            eprintln!("usage: cargo xtask <build|run|test> [--debug]");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("\nxtask: error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn target_dir() -> PathBuf {
    root().join("target")
}

fn digest_hex(data: &[u8]) -> String {
    blake2b::hash(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn step(msg: &str) {
    println!("\x1b[1;36m==>\x1b[0m {msg}");
}

fn cargo() -> Command {
    let mut cmd = Command::new(env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    cmd.current_dir(root());
    cmd
}

fn status(mut cmd: Command, what: &str) -> Result<()> {
    let st = cmd.status().map_err(|e| format!("{what}: {e}"))?;
    if st.success() {
        Ok(())
    } else {
        Err(format!("{what} failed ({st})"))
    }
}

fn read(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))
}

fn write(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    }
    fs::write(path, data).map_err(|e| format!("writing {}: {e}", path.display()))
}

/// Builds the user programs and the kernel and assembles the EFI system partition.
fn build(release: bool, qemu_exit: bool) -> Result<PathBuf> {
    step("building user programs (release)");
    let mut cmd = cargo();
    cmd.args([
        "build",
        "--release",
        "--target",
        TARGET,
        "-p",
        "kalkan-init",
        "-p",
        "kalkan-sandbox",
    ]);
    status(cmd, "cargo build (user)")?;

    let user_dir = target_dir().join(TARGET).join("release");
    let mut modules = Vec::new();
    for (name, bin) in [("init", "kalkan-init"), ("sandbox", "kalkan-sandbox")] {
        let data = read(&user_dir.join(bin))?;
        let image = elf::parse(&data, &elf::Limits::default())
            .map_err(|e| format!("{bin} rejected by the kernel's ELF validator: {e:?}"))?;
        let digest = digest_hex(&data);
        println!(
            "    {name:<8} {:>7} bytes, {} segments, {} relocations, blake2b {}...",
            data.len(),
            image.segments.len(),
            image.relocations.len(),
            &digest[..16]
        );
        modules.push((name, data, digest));
    }

    step(&format!(
        "building kernel ({})",
        if release { "release" } else { "debug" }
    ));
    let mut cmd = cargo();
    cmd.args(["build", "--target", TARGET, "-p", "kalkan-kernel"]);
    if release {
        cmd.arg("--release");
    }
    if qemu_exit {
        cmd.args(["--features", "qemu-exit"]);
    }
    cmd.env("KALKAN_INIT_BLAKE2B", &modules[0].2);
    cmd.env("KALKAN_SANDBOX_BLAKE2B", &modules[1].2);
    status(cmd, "cargo build (kernel)")?;
    let profile = if release { "release" } else { "debug" };
    let kernel = read(&target_dir().join(TARGET).join(profile).join("kalkan"))?;
    let kernel_digest = digest_hex(&kernel);
    println!(
        "    kernel   {:>7} bytes, blake2b {}...",
        kernel.len(),
        &kernel_digest[..16]
    );

    let limine = fetch_limine()?;

    step("assembling the EFI system partition");
    let esp = target_dir().join("esp");
    if esp.exists() {
        fs::remove_dir_all(&esp).map_err(|e| format!("cleaning {}: {e}", esp.display()))?;
    }
    write(&esp.join("EFI/BOOT/BOOTX64.EFI"), &limine)?;
    write(&esp.join("boot/kalkan"), &kernel)?;
    let mut conf = String::from(
        "# Generated by `cargo xtask`. Every file carries a BLAKE2b-512 digest that\n\
         # Limine verifies before loading it.\n\
         timeout: 0\n\
         \n\
         /Kalkan\n    protocol: limine\n    kaslr: yes\n",
    );
    conf.push_str(&format!("    path: boot():/boot/kalkan#{kernel_digest}\n"));
    for (name, data, digest) in &modules {
        write(&esp.join("boot").join(name), data)?;
        conf.push_str(&format!("    module_path: boot():/boot/{name}#{digest}\n"));
        conf.push_str(&format!("    module_string: {name}\n"));
    }
    write(&esp.join("boot/limine/limine.conf"), conf.as_bytes())?;
    println!("    {}", esp.display());
    Ok(esp)
}

/// Fetches the pinned Limine release and verifies it.
fn fetch_limine() -> Result<Vec<u8>> {
    let dir = target_dir().join(format!("limine-{LIMINE_TAG}"));
    if !dir.join("BOOTX64.EFI").exists() {
        step(&format!("fetching Limine {LIMINE_TAG}"));
        let _ = fs::remove_dir_all(&dir);
        let mut cmd = Command::new("git");
        cmd.args([
            "-c",
            "advice.detachedHead=false",
            "clone",
            "--quiet",
            "--depth",
            "1",
        ])
        .args(["--branch", LIMINE_TAG, LIMINE_URL])
        .arg(&dir)
        .env("GIT_TERMINAL_PROMPT", "0");
        status(cmd, "git clone (Limine)")?;
    }
    let out = Command::new("git")
        .arg("-C")
        .arg(&dir)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|e| format!("git rev-parse: {e}"))?;
    let commit = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if commit != LIMINE_COMMIT {
        return Err(format!(
            "Limine commit mismatch: expected {LIMINE_COMMIT}, got {commit}"
        ));
    }
    let efi = read(&dir.join("BOOTX64.EFI"))?;
    let expected = hex::decode::<64>(LIMINE_EFI_BLAKE2B).ok_or("bad pinned digest")?;
    if !hex::ct_eq(&expected, &blake2b::hash(&efi)) {
        return Err("Limine BOOTX64.EFI digest mismatch: refusing to use it".into());
    }
    println!(
        "    Limine {LIMINE_TAG} verified (commit {}, BLAKE2b pinned)",
        &LIMINE_COMMIT[..12]
    );
    Ok(efi)
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
    let qemu_share = qemu.parent().map(|d| d.join("share")).unwrap_or_default();
    let pairs: [(PathBuf, PathBuf); 8] = [
        (
            qemu_share.join("edk2-x86_64-code.fd"),
            qemu_share.join("edk2-i386-vars.fd"),
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

/// Builds the QEMU command line for booting `esp`.
fn qemu_command(esp: &Path) -> Result<Command> {
    let qemu = find_qemu()?;
    let (code, vars) = find_ovmf(&qemu)?;
    let target = target_dir();
    let esp_rel = esp
        .strip_prefix(&target)
        .map_err(|_| "ESP outside target dir")?;

    let mut cmd = Command::new(&qemu);
    cmd.current_dir(&target)
        .args(["-machine", "q35", "-cpu", "max", "-m", "256M", "-smp", "1"])
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
    step(&format!("booting {esp_arg} in QEMU ({})", qemu.display()));
    Ok(cmd)
}

/// Boots interactively with the serial console on stdout.
fn run(esp: &Path) -> Result<()> {
    let st = qemu_command(esp)?
        .status()
        .map_err(|e| format!("starting QEMU: {e}"))?;
    match st.code() {
        Some(0 | QEMU_SUCCESS) => Ok(()),
        other => Err(format!("QEMU exited with {other:?}")),
    }
}

/// Boots headless with a time limit; returns QEMU's exit code and the serial log.
fn run_headless(esp: &Path, log_name: &str) -> Result<(Option<i32>, Vec<String>)> {
    let mut child = qemu_command(esp)?
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .stdin(Stdio::null())
        .spawn()
        .map_err(|e| format!("starting QEMU: {e}"))?;
    let stdout = child.stdout.take().ok_or("no QEMU stdout")?;
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut log = Vec::new();
        for line in BufReader::new(stdout)
            .split(b'\n')
            .map_while(std::result::Result::ok)
        {
            let mut out = std::io::stdout().lock();
            let _ = out.write_all(&line);
            let _ = out.write_all(b"\n");
            log.push(String::from_utf8_lossy(&line).into_owned());
        }
        let _ = tx.send(log);
    });

    let start = Instant::now();
    let exit = loop {
        if let Some(st) = child.try_wait().map_err(|e| e.to_string())? {
            break st.code();
        }
        if start.elapsed() > TEST_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("timed out after {}s", TEST_TIMEOUT.as_secs()));
        }
        thread::sleep(Duration::from_millis(100));
    };
    let log = rx.recv_timeout(Duration::from_secs(5)).unwrap_or_default();
    let _ = write(&target_dir().join(log_name), log.join("\n").as_bytes());
    println!();
    Ok((exit, log))
}

fn copy_dir(from: &Path, to: &Path) -> Result<()> {
    fs::create_dir_all(to).map_err(|e| format!("creating {}: {e}", to.display()))?;
    for entry in fs::read_dir(from).map_err(|e| format!("reading {}: {e}", from.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let dst = to.join(entry.file_name());
        if entry.path().is_dir() {
            copy_dir(&entry.path(), &dst)?;
        } else {
            fs::copy(entry.path(), &dst).map_err(|e| format!("copying {}: {e}", dst.display()))?;
        }
    }
    Ok(())
}

/// Runs the security test suite, then the boot integrity (tamper) test.
fn test(esp: &Path) -> Result<()> {
    let (exit, log) = run_headless(esp, "kalkan-test.log")?;
    let passed = log.iter().any(|l| l.contains("KALKAN-TEST: PASS"));
    if exit != Some(QEMU_SUCCESS) || !passed {
        return Err(format!(
            "security suite failed (QEMU exit {exit:?}, PASS line: {passed})"
        ));
    }
    step("security test suite PASSED");

    // An attacker with write access to the boot partition flips one byte of the
    // sandbox and strips its digest from limine.conf so the bootloader no longer
    // checks it. The kernel must still refuse to run the module.
    step("tamper test: one byte of the sandbox module is modified");
    let tampered = target_dir().join("esp-tampered");
    if tampered.exists() {
        fs::remove_dir_all(&tampered).map_err(|e| e.to_string())?;
    }
    copy_dir(esp, &tampered)?;
    let module = tampered.join("boot/sandbox");
    let mut data = read(&module)?;
    let mid = data.len() / 2;
    data[mid] ^= 0xff;
    write(&module, &data)?;
    let conf_path = tampered.join("boot/limine/limine.conf");
    let conf = String::from_utf8(read(&conf_path)?).map_err(|e| e.to_string())?;
    let conf: Vec<String> = conf
        .lines()
        .map(|l| match l.split_once("boot():/boot/sandbox#") {
            Some((prefix, _)) => format!("{prefix}boot():/boot/sandbox"),
            None => l.to_string(),
        })
        .collect();
    write(&conf_path, conf.join("\n").as_bytes())?;

    let (exit, log) = run_headless(&tampered, "kalkan-tamper.log")?;
    let refused = log
        .iter()
        .any(|l| l.contains("integrity check FAILED for boot module 'sandbox'"));
    let ran_user = log.iter().any(|l| l.contains("entering user space"));
    if exit == Some(QEMU_SUCCESS + 2) && refused && !ran_user {
        step("tamper test PASSED: the kernel refused the modified module");
        Ok(())
    } else {
        Err(format!(
            "tamper test failed (QEMU exit {exit:?}, refused: {refused}, user space started: {ran_user})"
        ))
    }
}
