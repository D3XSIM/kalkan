//! Static checks of the properties the project claims about its own source.
//!
//! These are cheap, run before every test run, and fail the build if someone
//! (accidentally) weakens one of the claims made in the README:
//!
//! * the kernel and the policy core have **no third-party dependencies**;
//! * `unsafe` is forbidden in `kcore` and confined to four kernel modules;
//! * the kernel never lifts SMAP (`stac`) and never returns with `sysret`;
//! * every CI action is pinned to a commit and the workflow token is read-only;
//! * the system call documentation lists every system call.

use std::fs;
use std::path::{Path, PathBuf};

use crate::{Result, root, step};

/// The only packages allowed to appear in `Cargo.lock`.
const WORKSPACE_PACKAGES: [&str; 6] = [
    "kalkan-core",
    "kalkan-kernel",
    "kalkan-init",
    "kalkan-sandbox",
    "libkalkan",
    "xtask",
];

/// Instructions that must not appear anywhere in the kernel.
const FORBIDDEN_INSTRUCTIONS: [&str; 6] = [
    "stac", "sysret", "sysretq", "sysretl", "sysexit", "sysexitq",
];

fn read(path: &Path) -> Result<String> {
    fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir).map_err(|e| format!("reading {}: {e}", dir.display()))? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.is_dir() {
            rust_files(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

/// Lines of `source` that are code (not `//` comments), with their line numbers.
fn code_lines(source: &str) -> impl Iterator<Item = (usize, &str)> {
    source
        .lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l))
        .filter(|(_, l)| !l.trim_start().starts_with("//"))
}

fn uses_unsafe(line: &str) -> bool {
    let mut rest = line;
    while let Some(pos) = rest.find("unsafe") {
        let before_ok = rest[..pos]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_alphanumeric() && c != '_');
        let after = rest[pos + "unsafe".len()..].trim_start();
        let keyword = ["{", "fn", "impl", "extern", "("]
            .iter()
            .any(|k| after.starts_with(k));
        if before_ok && keyword {
            return true;
        }
        rest = &rest[pos + "unsafe".len()..];
    }
    false
}

fn no_third_party_dependencies(problems: &mut Vec<String>) -> Result<()> {
    let lock = read(&root().join("Cargo.lock"))?;
    let mut packages = 0;
    for line in lock.lines() {
        if let Some(name) = line
            .strip_prefix("name = \"")
            .and_then(|l| l.strip_suffix('"'))
        {
            packages += 1;
            if !WORKSPACE_PACKAGES.contains(&name) {
                problems.push(format!("Cargo.lock contains a third-party package: {name}"));
            }
        }
        if line.starts_with("source = ") {
            problems.push(format!("Cargo.lock references an external source: {line}"));
        }
    }
    if packages != WORKSPACE_PACKAGES.len() {
        problems.push(format!(
            "Cargo.lock lists {packages} packages, expected {}",
            WORKSPACE_PACKAGES.len()
        ));
    }
    Ok(())
}

fn unsafe_is_confined(problems: &mut Vec<String>) -> Result<()> {
    let root = root();
    if !read(&root.join("kcore/src/lib.rs"))?.contains("#![forbid(unsafe_code)]") {
        problems.push("kcore no longer forbids unsafe code".into());
    }
    let main = read(&root.join("kernel/src/main.rs"))?;
    if !main.contains("#![deny(unsafe_code)]") {
        problems.push("the kernel crate no longer denies unsafe code".into());
    }
    let allowed: Vec<&str> = main
        .lines()
        .zip(main.lines().skip(1))
        .filter(|(attr, _)| attr.trim() == "#[allow(unsafe_code)]")
        .map(|(_, item)| item.trim())
        .collect();
    if allowed != ["mod arch;", "mod boot;", "mod mm;", "mod sync;"] {
        problems.push(format!(
            "unsafe code is allowed in unexpected kernel modules: {allowed:?}"
        ));
    }

    // Belt and braces: the modules that must be free of `unsafe` really are.
    let mut files = Vec::new();
    rust_files(&root.join("kcore/src"), &mut files)?;
    rust_files(&root.join("kernel/src/kernel"), &mut files)?;
    for name in ["log.rs", "panic.rs", "posture.rs", "main.rs"] {
        files.push(root.join("kernel/src").join(name));
    }
    for file in files {
        let source = read(&file)?;
        for (n, line) in code_lines(&source) {
            if uses_unsafe(line) {
                problems.push(format!(
                    "unsafe code outside the allowed modules: {}:{n}",
                    file.display()
                ));
            }
        }
    }
    Ok(())
}

fn no_forbidden_instructions(problems: &mut Vec<String>) -> Result<()> {
    let mut files = Vec::new();
    rust_files(&root().join("kernel/src"), &mut files)?;
    for file in files {
        let source = read(&file)?;
        for (n, line) in code_lines(&source) {
            let lower = line.to_ascii_lowercase();
            for word in lower.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
                if FORBIDDEN_INSTRUCTIONS.contains(&word) {
                    problems.push(format!(
                        "forbidden instruction `{word}` at {}:{n}",
                        file.display()
                    ));
                }
            }
        }
    }
    Ok(())
}

fn ci_is_pinned(problems: &mut Vec<String>) -> Result<()> {
    let dir = root().join(".github/workflows");
    for entry in fs::read_dir(&dir).map_err(|e| format!("reading {}: {e}", dir.display()))? {
        let path = entry.map_err(|e| e.to_string())?.path();
        let text = read(&path)?;
        if !text.contains("permissions:\n  contents: read") {
            problems.push(format!(
                "{}: the workflow token is not read-only",
                path.display()
            ));
        }
        for (n, line) in text.lines().enumerate() {
            let Some(action) = line
                .trim()
                .strip_prefix("- uses:")
                .or(line.trim().strip_prefix("uses:"))
            else {
                continue;
            };
            let reference = action.split('#').next().unwrap_or("").trim();
            let pinned = reference.rsplit_once('@').is_some_and(|(_, rev)| {
                rev.len() == 40 && rev.chars().all(|c| c.is_ascii_hexdigit())
            });
            if !pinned {
                problems.push(format!(
                    "{}:{}: action not pinned to a commit: {reference}",
                    path.display(),
                    n + 1
                ));
            }
        }
    }
    Ok(())
}

fn docs_list_every_syscall(problems: &mut Vec<String>) -> Result<()> {
    let docs = read(&root().join("docs/SYSCALLS.md"))?;
    let table = docs.split("## Errors").next().unwrap_or("");
    let mut numbers: Vec<u64> = table
        .lines()
        .filter_map(|l| l.strip_prefix("| ")?.split(' ').next()?.parse().ok())
        .collect();
    numbers.sort_unstable();
    let expected: Vec<u64> = (0..kcore::abi::sys::COUNT).collect();
    if numbers != expected {
        problems.push(format!(
            "docs/SYSCALLS.md documents system calls {numbers:?}, the ABI defines 0..{}",
            kcore::abi::sys::COUNT
        ));
    }
    Ok(())
}

/// Runs every static check.
pub fn run() -> Result<()> {
    step("static checks (dependencies, unsafe confinement, forbidden instructions, CI pinning)");
    let mut problems = Vec::new();
    no_third_party_dependencies(&mut problems)?;
    unsafe_is_confined(&mut problems)?;
    no_forbidden_instructions(&mut problems)?;
    ci_is_pinned(&mut problems)?;
    docs_list_every_syscall(&mut problems)?;
    if problems.is_empty() {
        println!("    all static checks passed");
        Ok(())
    } else {
        for p in &problems {
            println!("    PROBLEM: {p}");
        }
        Err(format!("{} static check(s) failed", problems.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::uses_unsafe;

    #[test]
    fn detects_unsafe_code() {
        assert!(uses_unsafe("    unsafe { foo() }"));
        assert!(uses_unsafe("pub unsafe fn x() {}"));
        assert!(uses_unsafe("unsafe impl Sync for X {}"));
        assert!(uses_unsafe("#[unsafe(no_mangle)]"));
        assert!(uses_unsafe("unsafe extern \"C\" {"));
        assert!(!uses_unsafe("#![forbid(unsafe_code)]"));
        assert!(!uses_unsafe("let not_unsafe_at_all = 1;"));
        assert!(!uses_unsafe("// the word unsafe in prose"));
    }
}
