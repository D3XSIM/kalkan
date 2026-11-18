//! Build and test orchestration for Kalkan.
//!
//! ```text
//! cargo xtask build [--debug]   build everything and assemble the boot partition
//! cargo xtask run   [--debug]   build and boot in QEMU (serial console on stdout)
//! cargo xtask check             static checks of the project's security claims
//! cargo xtask test  [--quick]   static checks + every QEMU scenario (what CI runs)
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

mod checks;
mod qemu;
mod scenarios;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use kcore::{blake2b, elf, hex};

const TARGET: &str = "x86_64-unknown-none";
const LIMINE_URL: &str = "https://github.com/Limine-Bootloader/Limine.git";
const LIMINE_TAG: &str = "v11.2.1-binary";
const LIMINE_COMMIT: &str = "deba356b4a70ee183ec3214864f0ba2ffe510b8c";
const LIMINE_EFI_BLAKE2B: &str = "d71f8846f3a3c0368d64ae73758901ca647b69f834a83ccf67766503812c3515\
                                  646e56529275f980abbdfd83492944348343b96f9a338da757dea34263d626aa";

type Result<T> = std::result::Result<T, String>;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let flag = |name: &str| args.iter().any(|a| a == name);
    let release = !flag("--debug");
    let result = match args.first().map(String::as_str) {
        Some("build") => build(release, "").map(|_| ()),
        Some("run") => build(release, "qemu-exit").and_then(|esp| qemu::run_interactive(&esp)),
        Some("check") => checks::run(),
        Some("test") => checks::run()
            .and_then(|()| build(true, "qemu-exit,audit"))
            .and_then(|esp| scenarios::run(&esp, flag("--quick"))),
        _ => {
            eprintln!("usage: cargo xtask <build|run|check|test> [--debug] [--quick]");
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
fn build(release: bool, features: &str) -> Result<PathBuf> {
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
    if !features.is_empty() {
        cmd.args(["--features", features]);
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
