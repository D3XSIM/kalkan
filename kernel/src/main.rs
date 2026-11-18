//! # Kalkan
//!
//! A capability-based, security-first microkernel for x86-64, written in Rust.
//!
//! `unsafe` code is confined to four modules — `arch`, `boot`, `mm` and `sync` —
//! and is **denied by the compiler everywhere else**. All access-control policy
//! lives in the `kcore` crate, which forbids `unsafe` entirely and is tested and
//! fuzzed on the host.

#![no_std]
#![no_main]
#![deny(unsafe_code)]

extern crate alloc;

#[allow(unsafe_code)]
mod arch;
#[allow(unsafe_code)]
mod boot;
#[allow(unsafe_code)]
mod mm;
#[allow(unsafe_code)]
mod sync;

mod kernel;
mod log;
mod panic;
mod posture;

use alloc::vec::Vec;

use kcore::chacha20::ChaChaRng;

use crate::arch::cpu::{Features, Posture};
use crate::arch::rng::Sources;
use crate::log::Addr;
use crate::mm::MemoryMap;
use crate::mm::kspace::Layout;
use crate::sync::SpinLock;

const BANNER: &str = r"
  _  __     _ _
 | |/ /__ _| | | ____ _ _ __
 | ' // _` | | |/ / _` | '_ \
 | . \ (_| | |   < (_| | | | |
 |_|\_\__,_|_|_|\_\__,_|_| |_|   capability microkernel
";

/// The link-time base address of the kernel image (see `linker.ld`).
const LINK_BASE: u64 = 0xffff_ffff_8000_0000;

/// The boot modules the kernel expects — and the only ones it accepts.
const MODULE_NAMES: [&str; 2] = ["init", "sandbox"];

/// State carried from the bootloader stack to the kernel stack.
struct BootState {
    map: MemoryMap,
    modules: boot::Modules,
    layout: Layout,
    rng: ChaChaRng,
    features: Features,
    posture: Posture,
    seed: Sources,
}

static BOOT: SpinLock<Option<BootState>> = SpinLock::new(None);

/// Stage 1: runs on the bootloader's stack and page tables.
pub(crate) extern "C" fn boot_main() -> ! {
    arch::serial::init();
    kprintln!("{BANNER}");
    kprintln!("Kalkan v{} booting", env!("CARGO_PKG_VERSION"));
    let (loader, version) = boot::bootloader();
    kprintln!("[boot] bootloader: {loader} {version}");
    assert!(
        boot::base_revision_supported(),
        "bootloader does not support Limine base revision 6"
    );
    let _ = boot::touch_markers();

    let hhdm = boot::hhdm_offset().expect("no HHDM response from the bootloader");
    mm::set_hhdm(hhdm);
    if let Some((phys, virt)) = boot::kernel_address() {
        kprintln!(
            "[boot] kernel image at {} (physical {})",
            Addr(virt),
            Addr(phys)
        );
    }
    // Boot modules are recorded as physical ranges: the bootloader's direct map
    // (and every pointer into it) disappears when the kernel installs its own.
    let modules = boot::Modules::capture(&MODULE_NAMES);

    arch::gdt::init();
    arch::idt::init();

    assert!(
        !arch::cpu::five_level_paging(),
        "5-level paging is active; this kernel only supports 4-level paging"
    );
    let features = arch::cpu::detect();
    let vendor = core::str::from_utf8(&features.vendor).unwrap_or("?");
    kprintln!("[cpu] vendor {vendor}");
    let posture = match arch::cpu::harden(&features) {
        Ok(p) => p,
        Err(missing) => panic!("CPU lacks mandatory protection {missing:?}: refusing to boot"),
    };
    let _ = arch::cpu::enable_mitigations(&features);

    let (seed, sources) = arch::rng::seed(&features);
    let mut rng = ChaChaRng::from_seed(seed);

    let map = boot::memory_map();
    mm::frame::init(&map);
    let (free, total) = mm::frame::stats();
    kprintln!(
        "[mm] {} MiB usable of {} MiB tracked",
        free / 256,
        total / 256
    );

    // In x2APIC mode the local APIC is programmed through MSRs: its MMIO page is
    // then not mapped at all.
    let lapic_mmio = (!features.x2apic).then(arch::apic::physical_base);
    let layout = mm::kspace::build(&map, lapic_mmio, &mut rng);

    *BOOT.lock() = Some(BootState {
        map,
        modules,
        layout,
        rng,
        features,
        posture,
        seed: sources,
    });
    mm::kspace::enter(stage2)
}

/// Verifies every boot module against the digest compiled into the kernel.
fn verified_modules(modules: &boot::Modules) -> Vec<(&'static str, &'static [u8])> {
    let digests = [
        option_env!("KALKAN_INIT_BLAKE2B"),
        option_env!("KALKAN_SANDBOX_BLAKE2B"),
    ];
    kprintln!("Boot module integrity (BLAKE2b-512):");
    let mut verified = Vec::new();
    for (index, (name, digest)) in MODULE_NAMES.into_iter().zip(digests).enumerate() {
        let data = modules
            .data(index)
            .unwrap_or_else(|| panic!("boot module '{name}' is missing"));
        let digest = digest.unwrap_or_else(|| {
            panic!("no reference digest for '{name}' compiled in (build with `cargo xtask`)")
        });
        let expected = kcore::hex::decode::<64>(digest).expect("malformed reference digest");
        let actual = kcore::blake2b::hash(data);
        assert!(
            kcore::hex::ct_eq(&expected, &actual),
            "integrity check FAILED for boot module '{name}': refusing to run it"
        );
        let mut short = alloc::string::String::new();
        for b in &actual[..8] {
            short.push(kcore::hex::digit(b >> 4));
            short.push(kcore::hex::digit(b & 0xf));
        }
        kprintln!(
            "  [\x1b[32mPASS\x1b[0m] {name:<8} {:>7} bytes  {short}...",
            data.len()
        );
        verified.push((name, data));
    }
    if modules.total != verified.len() {
        panic!("unexpected extra boot modules: refusing to boot");
    }
    verified
}

/// Stage 2: runs on the kernel's own stack and page tables.
extern "C" fn stage2() -> ! {
    let BootState {
        map,
        modules,
        layout,
        mut rng,
        features,
        posture,
        seed,
    } = BOOT.lock().take().expect("boot state");

    // The guarded stacks exist only in the kernel's own page tables: the TSS may
    // point at them only now (until here, the early stacks in the image are used).
    arch::gdt::set_interrupt_stacks(layout.ist_tops);
    arch::gdt::set_kernel_stack(layout.stack_top);
    mm::heap::init(layout.heap_base, &mut rng);
    arch::syscall::init(layout.stack_top);
    arch::apic::init(features.x2apic, layout.lapic_virt);
    kprintln!(
        "[mm] kernel page tables active; direct map at {}; local APIC in {} mode",
        Addr(layout.direct_map),
        if arch::apic::is_x2apic() {
            "x2APIC"
        } else {
            "xAPIC"
        }
    );

    let slide = layout.kernel_virt.wrapping_sub(LINK_BASE);
    posture::verify(&features, &posture, &layout, &seed, slide);

    let modules = verified_modules(&modules);
    rng.reseed(&arch::rdtsc().to_le_bytes());
    let landmarks = kernel::Landmarks {
        text: layout.text.0,
        data: layout.data.0,
        direct_map: layout.direct_map + layout.kernel_phys,
        stack: layout.stack_top - 8,
    };
    kernel::init(rng, &modules, landmarks);

    let reclaimed = mm::frame::reclaim_bootloader_memory(&map);
    kprintln!(
        "[mm] reclaimed and zeroed {} KiB of bootloader memory",
        reclaimed * 4
    );
    kprintln!("[kernel] entering user space");
    kernel::run(layout.stack_top)
}
