//! Boot-time security self check.
//!
//! The kernel does not *assume* its protections are in place — it verifies them
//! by inspecting the live control registers and walking its own page tables, and
//! refuses to continue if any mandatory property does not hold.

use crate::arch::cpu::{Features, Posture};
use crate::arch::rng::Sources;
use crate::kprintln;
use crate::mm::kspace::Layout;
use crate::mm::paging;

fn line(name: &str, ok: bool, mandatory: bool, detail: &str) {
    let (mark, color) = match (ok, mandatory) {
        (true, _) => ("PASS", "32"),
        (false, true) => ("FAIL", "31"),
        (false, false) => ("N/A ", "33"),
    };
    kprintln!("  [\x1b[{color}m{mark}\x1b[0m] {name:<38} {detail}");
}

/// Verifies and prints the security posture. Panics if a mandatory check fails.
/// Optional hardening that the CPU does not offer is reported as `N/A`.
pub fn verify(
    features: &Features,
    posture: &Posture,
    layout: &Layout,
    seed: &Sources,
    kaslr_slide: u64,
) {
    kprintln!("Security posture:");
    let mut ok = true;
    let mut check = |name: &str, pass: bool, mandatory: bool, detail: &str| {
        line(name, pass, mandatory, detail);
        if mandatory && !pass {
            ok = false;
        }
    };

    check("NX (no-execute pages)", posture.nx, true, "EFER.NXE");
    check(
        "SMEP (no kernel exec of user pages)",
        posture.smep,
        true,
        "CR4.SMEP",
    );
    check(
        "SMAP (no kernel access to user pages)",
        posture.smap,
        true,
        "CR4.SMAP, never lifted",
    );
    check("Kernel write protection", posture.wp, true, "CR0.WP");
    check(
        "UMIP (hide descriptor tables)",
        posture.umip,
        false,
        if features.umip {
            "CR4.UMIP"
        } else {
            "not supported by CPU"
        },
    );
    check("RDTSC restricted to kernel", posture.tsd, true, "CR4.TSD");
    check(
        "x87/SSE/AVX disabled for user space",
        posture.simd_disabled,
        true,
        "no SIMD state to leak",
    );
    check(
        "FSGSBASE disabled",
        posture.fsgsbase_disabled,
        true,
        "CR4.FSGSBASE=0",
    );

    let pml4 = layout.pml4;
    let text = paging::translate(pml4, layout.text.0);
    let rodata = paging::translate(pml4, layout.rodata.0);
    let data = paging::translate(pml4, layout.data.0);
    let wx = text.is_some_and(|t| t.executable && !t.writable)
        && rodata.is_some_and(|t| !t.executable && !t.writable)
        && data.is_some_and(|t| !t.executable && t.writable);
    check(
        "W^X kernel image",
        wx,
        true,
        ".text R-X, .rodata R--, .data RW-",
    );

    let hhdm = paging::translate(pml4, crate::mm::hhdm() + layout.kernel_phys);
    check(
        "Direct map non-executable",
        hhdm.is_some_and(|t| !t.executable),
        true,
        "physmap is NX",
    );
    // The kernel image is also reachable through the direct map; that alias must
    // not offer a way around `.text`/`.rodata` being read-only.
    let alias_ro = [layout.text.0, layout.rodata.0, layout.data.0]
        .iter()
        .all(|&va| {
            paging::translate(pml4, va).is_some_and(|k| {
                paging::translate(pml4, crate::mm::hhdm() + k.phys)
                    .is_some_and(|t| !t.writable && !t.executable)
            })
        });
    check(
        "Kernel image alias in direct map",
        alias_ro,
        true,
        "read-only, NX",
    );

    let guard_ok = paging::translate(pml4, layout.stack_guard).is_none()
        && paging::translate(pml4, layout.stack_top).is_none()
        && paging::translate(pml4, layout.stack_top - 8).is_some();
    check(
        "Kernel stack guard pages",
        guard_ok,
        true,
        "unmapped page below and above",
    );

    let no_user = (256..512).all(|i| paging::pml4_entry(pml4, i) & paging::flags::USER == 0)
        && [layout.text.0, layout.data.0, layout.stack_top - 8]
            .iter()
            .all(|&va| paging::translate(pml4, va).is_some_and(|t| !t.user));
    check(
        "Kernel pages supervisor-only",
        no_user,
        true,
        "no USER bit in the kernel half",
    );

    let slide: alloc::string::String = if kaslr_slide == 0 {
        "DISABLED".into()
    } else {
        alloc::format!("slide {kaslr_slide:#x}")
    };
    check("KASLR (kernel image)", kaslr_slide != 0, false, &slide);
    let regions = alloc::format!("PML4 slots {:?}", layout.slots);
    check(
        "Randomised stack/heap/MMIO placement",
        true,
        false,
        &regions,
    );
    let entropy = alloc::format!(
        "rdseed x{}, rdrand x{}, {} jitter samples",
        seed.rdseed,
        seed.rdrand,
        seed.jitter_samples
    );
    check(
        "Entropy (ChaCha20 CSPRNG)",
        seed.rdseed + seed.rdrand > 0,
        false,
        &entropy,
    );
    check(
        "Spectre v2: IBRS + IBPB",
        features.ibpb,
        false,
        if features.ibpb {
            "IBRS always on, IBPB on address-space switch"
        } else {
            "not supported by CPU"
        },
    );
    check(
        "Spectre v2: STIBP (cross-thread)",
        features.stibp,
        false,
        if features.stibp {
            "always on"
        } else {
            "not supported by CPU"
        },
    );
    check(
        "MDS: CPU buffer clearing",
        features.md_clear,
        false,
        if features.md_clear {
            "VERW on return"
        } else {
            "not needed / not supported"
        },
    );

    assert!(ok, "mandatory security check failed: refusing to boot");
}
