//! Whole-system test scenarios.
//!
//! 1. **The adversarial suite** on a test kernel on several machines (little
//!    memory, memory above 4 GiB, local APIC in x2APIC and in xAPIC mode): every
//!    test must pass, the kernel's self-audit must hold, and nothing printed by an
//!    untrusted process may contain terminal escape sequences.
//! 2. **A production kernel** (no `selftest` feature) must have none of the test
//!    facilities, must keep every address out of its log, and must still pass
//!    every test that does not depend on them.
//! 3. **Randomisation**: kernel image, direct map, kernel regions and user programs
//!    must land at different addresses on different boots.
//! 4. **Fail-closed CPU checks**: on CPUs without NX, SMEP or SMAP the kernel must
//!    refuse to boot.
//! 5. **Boot chain tampering**: modified, swapped, added or missing boot modules
//!    and a modified kernel must never reach user space.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::qemu::{self, Boot, Machine};
use crate::{Result, read, step, target_dir, write};

const SUITE_TIMEOUT: Duration = Duration::from_secs(600);
const REFUSAL_TIMEOUT: Duration = Duration::from_secs(120);

/// Facts extracted from the log of a successful suite run.
#[derive(Debug)]
struct Facts {
    apic: String,
    kernel_image: String,
    direct_map: String,
    kernel_regions: String,
    init_base: String,
    sandbox_base: String,
}

fn fact(boot: &Boot, marker: &str) -> Result<String> {
    boot.value_after(marker)
        .ok_or_else(|| format!("log line with `{marker}` not found"))
}

/// Lines printed by user processes (the kernel prefixes them with the name).
fn from_user(line: &str) -> bool {
    line.starts_with("[init]") || line.starts_with("[sandbox]") || line.starts_with("[probe")
}

/// Problems shared by every boot that runs the suite to the end.
fn common_problems(boot: &qemu::Boot, problems: &mut Vec<String>) {
    if boot.timed_out {
        problems.push("timed out".to_string());
    }
    if boot.exit != Some(qemu::EXIT_SUCCESS) {
        problems.push(format!("QEMU exit status {:?}", boot.exit));
    }
    for required in [
        "KALKAN-TEST: PASS",
        "[kernel] audit: object graph consistent",
        "[kernel] system shut down cleanly",
        // No debug trap may leak into the kernel (the single-step probes try).
        " 0 kernel-mode debug traps",
        // Printed through buffers that cross / end at a page boundary.
        "[init] KALKAN-CROSS-PAGE-COPY-OK",
        "[sandbox] end-of-the-page!",
    ] {
        if !boot.has(required) {
            problems.push(format!("missing log line: {required}"));
        }
    }
    for forbidden in [
        "KERNEL PANIC",
        "AUDIT FAILED",
        "[FAIL]",
        "[ESCAPED]",
        "[BROKEN]",
        "NOT STOPPED",
    ] {
        if boot.has(forbidden) {
            problems.push(format!("log contains: {forbidden}"));
        }
    }
    // Output of user processes is untrusted: the kernel must have neutralised
    // every escape sequence (the sandbox tries to inject one).
    let injected = boot.raw.iter().any(|l| from_user(l) && l.contains('\x1b'));
    if injected || !boot.has("?[2J?[31mFAKE KERNEL LOG?[0m") {
        problems.push("terminal escape sequences from a user process reached the console".into());
    }
}

/// Runs the adversarial suite on a test kernel and verifies the complete log;
/// `apic` is the local APIC mode the kernel must have chosen on this CPU.
fn suite(esp: &Path, machine: &Machine<'_>, log: &str, echo: bool, apic: &str) -> Result<Facts> {
    step(&format!(
        "security suite on {} RAM, CPU `{}`",
        machine.memory, machine.cpu
    ));
    // A bootloader panic (for example: too little memory) ends the run right away.
    let boot = qemu::boot(esp, machine, log, SUITE_TIMEOUT, echo, Some("PANIC: "))?;
    if echo {
        println!();
    }
    let mut problems = Vec::new();
    common_problems(&boot, &mut problems);
    for required in [
        "probe processes created (inactive); test kernel",
        "on a test kernel...",
        "--- process life cycle",
        &format!("local APIC in {apic} mode"),
    ] {
        if !boot.has(required) {
            problems.push(format!("missing log line: {required}"));
        }
    }
    if boot.has("[SKIP]") {
        problems.push("tests were skipped on a test kernel".into());
    }
    if !problems.is_empty() {
        return Err(format!(
            "security suite failed (see target/{log}): {}",
            problems.join("; ")
        ));
    }

    let tests = fact(&boot, "PASS - all ")?;
    let facts = Facts {
        apic: fact(&boot, "local APIC in ")?,
        kernel_image: fact(&boot, "kernel image at ")?,
        direct_map: fact(&boot, "direct map at ")?,
        kernel_regions: boot
            .log
            .iter()
            .find_map(|l| l.split_once("PML4 slots ").map(|(_, s)| s.to_string()))
            .ok_or("kernel region slots not found")?,
        init_base: fact(&boot, "relocations, base ")?,
        sandbox_base: boot
            .log
            .iter()
            .find(|l| l.contains("[loader] 'sandbox'"))
            .and_then(|l| {
                l.split_once("base ")
                    .map(|(_, s)| s.split(',').next().unwrap_or("").to_string())
            })
            .ok_or("sandbox base not found")?,
    };
    let audits = fact(&boot, "address spaces); ").unwrap_or_default();
    println!(
        "    PASSED: {tests} security tests, {audits} kernel audits, kernel at {}, {} APIC",
        facts.kernel_image, facts.apic
    );
    Ok(facts)
}

/// `true` if `line` contains a hexadecimal number long enough to be an address.
fn shows_address(line: &str) -> bool {
    line.match_indices("0x").any(|(at, _)| {
        line[at + 2..]
            .chars()
            .take_while(char::is_ascii_hexdigit)
            .count()
            >= 8
    })
}

/// A kernel built without the `selftest` feature: no probe processes, no test-only
/// system calls, no addresses in its log — and the suite still passes everything
/// that does not depend on the test facilities.
fn production_kernel(esp: &Path) -> Result<()> {
    step("production kernel: no test facilities, no addresses in the log");
    let log = "kalkan-production.log";
    let boot = qemu::boot(
        esp,
        &Machine::default(),
        log,
        SUITE_TIMEOUT,
        false,
        Some("PANIC: "),
    )?;
    let mut problems = Vec::new();
    common_problems(&boot, &mut problems);
    for required in [
        "'sandbox' and 0 probe processes created (inactive)",
        "(not a test kernel)...",
        "[PASS] no kernel statistics outside test kernels",
        "[PASS] no kernel layout outside test kernels",
        "[PASS] no probe processes outside test kernels",
        "groups skipped: not a test kernel",
        "kernel image at <hidden>",
        "direct map at <hidden>",
        "slide <hidden>",
        "PML4 slots <hidden>",
        "base <hidden>, entry <hidden>",
    ] {
        if !boot.has(required) {
            problems.push(format!("missing log line: {required}"));
        }
    }
    if boot.has("; test kernel") {
        problems.push("the kernel calls itself a test kernel".into());
    }
    // Everything the kernel printed (firmware output before the banner aside).
    let banner = boot
        .log
        .iter()
        .position(|l| l.contains("Kalkan v"))
        .unwrap_or(0);
    if let Some(line) = boot.log[banner..]
        .iter()
        .find(|l| !from_user(l) && shows_address(l))
    {
        problems.push(format!("the kernel printed an address: {line}"));
    }
    if !problems.is_empty() {
        return Err(format!(
            "production kernel failed (see target/{log}): {}",
            problems.join("; ")
        ));
    }
    let tests = fact(&boot, "PASS - all ")?;
    println!("    PASSED: {tests} security tests; probes and diagnostics absent, addresses hidden");
    Ok(())
}

/// Different boots must not share their address space layout.
///
/// The first two runs must differ in *every* respect. Both machines have less
/// than 1 GiB of RAM, so the kernel draws each placement from the same range
/// on both: only randomness can make them differ. (The range of the direct map
/// depends on the amount of RAM, so a comparison with the 5 GiB machine alone
/// would prove nothing.)
fn randomisation(runs: &[Facts]) -> Result<()> {
    step("address space layout randomisation across boots");
    let mut weak = Vec::new();
    let mut check = |what: &str, get: &dyn Fn(&Facts) -> &str| {
        let values: Vec<&str> = runs.iter().map(get).collect();
        println!("    {what:<28} {}", values.join("  "));
        if values.len() < 2 || values[0] == values[1] {
            weak.push(what.to_string());
        }
    };
    check("kernel image", &|f| &f.kernel_image);
    check("direct map of physical memory", &|f| &f.direct_map);
    check("kernel stack/heap/MMIO slots", &|f| &f.kernel_regions);
    check("init (user ASLR)", &|f| &f.init_base);
    check("sandbox (user ASLR)", &|f| &f.sandbox_base);
    if weak.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "identical on every boot (not randomised): {}",
            weak.join(", ")
        ))
    }
}

/// The kernel must stop before user space with a message containing `needle`.
fn refuses(esp: &Path, machine: &Machine<'_>, name: &str, needle: &str) -> Result<()> {
    let log = format!("kalkan-{name}.log");
    let boot = qemu::boot(esp, machine, &log, REFUSAL_TIMEOUT, false, None)?;
    let refused = boot.exit == Some(qemu::EXIT_FAILURE)
        && boot.has(needle)
        && boot.has("System halted (fail-closed)")
        && !boot.has("entering user space");
    if refused {
        println!("    PASSED: {name}: \"{needle}\"");
        Ok(())
    } else {
        Err(format!(
            "{name}: the kernel did not refuse as expected (exit {:?}, timed out: {}, see target/{log})",
            boot.exit, boot.timed_out
        ))
    }
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

/// Creates a modified copy of the boot partition. `edit` receives the copy's
/// directory and the lines of its `limine.conf`.
fn variant(
    esp: &Path,
    name: &str,
    edit: impl FnOnce(&Path, &mut Vec<String>) -> Result<()>,
) -> Result<PathBuf> {
    let dir = target_dir().join(format!("esp-{name}"));
    if dir.exists() {
        fs::remove_dir_all(&dir).map_err(|e| e.to_string())?;
    }
    copy_dir(esp, &dir)?;
    let conf_path = dir.join("boot/limine/limine.conf");
    let conf = String::from_utf8(read(&conf_path)?).map_err(|e| e.to_string())?;
    let mut lines: Vec<String> = conf.lines().map(str::to_string).collect();
    edit(&dir, &mut lines)?;
    write(&conf_path, (lines.join("\n") + "\n").as_bytes())?;
    Ok(dir)
}

/// Removes the BLAKE2b digest from the config line that loads `file`, so the
/// bootloader no longer verifies it (what an attacker with write access to the
/// boot partition would do).
fn strip_digest(lines: &mut [String], file: &str) {
    for line in lines.iter_mut() {
        if let Some((path, _)) = line.split_once('#')
            && path.ends_with(&format!("/boot/{file}"))
        {
            *line = path.to_string();
        }
    }
}

fn flip_byte(path: &Path) -> Result<()> {
    let mut data = read(path)?;
    let middle = data.len() / 2;
    data[middle] ^= 0xff;
    write(path, &data)
}

fn boot_chain_tampering(esp: &Path, quick: bool) -> Result<()> {
    step("boot chain tampering (the kernel must refuse to start user space)");
    let machine = Machine::default();

    let dir = variant(esp, "tampered", |dir, conf| {
        strip_digest(conf, "sandbox");
        flip_byte(&dir.join("boot/sandbox"))
    })?;
    refuses(
        &dir,
        &machine,
        "one byte of a module flipped",
        "integrity check FAILED for boot module 'sandbox'",
    )?;
    if quick {
        return Ok(());
    }

    let dir = variant(esp, "swapped", |dir, conf| {
        strip_digest(conf, "init");
        strip_digest(conf, "sandbox");
        let (init, sandbox) = (
            read(&dir.join("boot/init"))?,
            read(&dir.join("boot/sandbox"))?,
        );
        write(&dir.join("boot/init"), &sandbox)?;
        write(&dir.join("boot/sandbox"), &init)
    })?;
    refuses(
        &dir,
        &machine,
        "modules swapped",
        "integrity check FAILED for boot module 'init'",
    )?;

    let dir = variant(esp, "truncated", |dir, conf| {
        strip_digest(conf, "init");
        let init = read(&dir.join("boot/init"))?;
        write(&dir.join("boot/init"), &init[..init.len() / 2])
    })?;
    refuses(
        &dir,
        &machine,
        "module truncated",
        "integrity check FAILED for boot module 'init'",
    )?;

    let dir = variant(esp, "extra", |dir, conf| {
        let sandbox = read(&dir.join("boot/sandbox"))?;
        write(&dir.join("boot/extra"), &sandbox)?;
        conf.push("    module_path: boot():/boot/extra".into());
        conf.push("    module_string: extra".into());
        Ok(())
    })?;
    refuses(
        &dir,
        &machine,
        "unexpected extra module",
        "unexpected extra boot modules",
    )?;

    let dir = variant(esp, "missing", |_, conf| {
        let Some(at) = conf.iter().position(|l| l.contains("/boot/sandbox")) else {
            return Err("sandbox module line not found".into());
        };
        conf.drain(at..at + 2); // module_path + module_string
        Ok(())
    })?;
    refuses(
        &dir,
        &machine,
        "module missing",
        "boot module 'sandbox' is missing",
    )?;

    // A modified kernel never even starts: the bootloader checks its digest and
    // stops with a message on the firmware console (which is not on the serial
    // line). A normal boot prints the kernel banner within a few seconds, so its
    // absence after a generous wait is the evidence.
    let dir = variant(esp, "kernel", |dir, _| flip_byte(&dir.join("boot/kalkan")))?;
    let boot = qemu::boot(
        &dir,
        &machine,
        "kalkan-tampered-kernel.log",
        Duration::from_secs(40),
        false,
        None,
    )?;
    if boot.has("Kalkan v") || boot.has("[boot]") {
        return Err("a modified kernel was started by the bootloader (see target/kalkan-tampered-kernel.log)".into());
    }
    // The bootloader stops at its error screen: QEMU must still be running. An
    // early exit (a crash, a configuration error) would prove nothing.
    if !boot.timed_out || boot.exit.is_some() {
        return Err(format!(
            "the boot with a modified kernel ended unexpectedly (exit {:?}; see \
             target/kalkan-tampered-kernel.log)",
            boot.exit
        ));
    }
    println!("    PASSED: one byte of the kernel flipped: never started by the bootloader");
    Ok(())
}

fn fail_closed_cpu_checks(esp: &Path) -> Result<()> {
    step("fail-closed checks on CPUs without mandatory protections");
    for (cpu, missing) in [("qemu64", "Smep"), ("max,-smap", "Smap"), ("max,-nx", "Nx")] {
        let machine = Machine {
            cpu,
            ..Machine::default()
        };
        refuses(
            esp,
            &machine,
            &format!("cpu-{}", cpu.replace(',', "")),
            &format!("CPU lacks mandatory protection {missing}"),
        )?;
    }
    Ok(())
}

/// Runs every scenario. With `quick`, only the suite on the default machine and
/// one tamper test are run. `esp` holds a test kernel, `production` (not needed
/// with `quick`) a normal one.
pub fn run(esp: &Path, production: Option<&Path>, quick: bool) -> Result<()> {
    // The local APIC is programmed through MSRs (x2APIC) when the CPU supports it
    // and through MMIO (xAPIC) otherwise: both paths are exercised.
    let x2apic = Machine {
        cpu: "max,+x2apic",
        ..Machine::default()
    };
    let default = suite(esp, &x2apic, "kalkan-test.log", true, "x2APIC")?;
    if !quick {
        let small = suite(
            esp,
            &Machine {
                memory: "128M",
                cpu: "max,-x2apic",
            },
            "kalkan-test-128M.log",
            false,
            "xAPIC",
        )?;
        let large = suite(
            esp,
            &Machine {
                memory: "5G",
                ..x2apic
            },
            "kalkan-test-5G.log",
            false,
            "x2APIC",
        )?;
        randomisation(&[default, small, large])?;
        production_kernel(production.ok_or("no production kernel was built")?)?;
        fail_closed_cpu_checks(esp)?;
    }
    boot_chain_tampering(esp, quick)?;
    step(if quick {
        "quick test run PASSED"
    } else {
        "all scenarios PASSED"
    });
    Ok(())
}
