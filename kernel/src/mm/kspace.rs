//! The kernel address space.
//!
//! At boot the kernel throws away the bootloader's page tables (which map
//! everything read-write-execute) and builds its own:
//!
//! | Region            | Permissions | Notes                                       |
//! |-------------------|-------------|---------------------------------------------|
//! | kernel `.text`    | `R-X`       | never writable                              |
//! | kernel `.rodata`  | `R--`       | includes relocated `.data.rel.ro` / `.got`  |
//! | kernel `.data`    | `RW-`       | never executable                            |
//! | direct map        | `RW-`       | **never executable**; RAM regions only      |
//! | kernel stack      | `RW-`       | guard pages below and above                 |
//! | IST stacks        | `RW-`       | guard pages between them                    |
//! | heap              | `RW-`       | grows page by page                          |
//! | local APIC        | `RW-` UC    |                                             |
//!
//! Stack, heap and MMIO regions are placed in randomly chosen top-level slots at
//! random offsets on every boot, on top of the bootloader's KASLR for the image.
//! No kernel page ever has the `USER` bit.

use core::sync::atomic::{AtomicU64, Ordering};

use kcore::chacha20::ChaChaRng;

use super::paging::{self, MapError, PageSize, flags::*};
use super::{MemoryMap, PAGE_SIZE, frame, hhdm};
use crate::arch;

const SIZE_2M: u64 = 2 << 20;
const STACK_PAGES: u64 = 16;
const IST_PAGES: u64 = 4;
/// Virtual size reserved for the kernel heap.
pub const HEAP_SIZE: u64 = 64 << 30;

static KERNEL_PML4: AtomicU64 = AtomicU64::new(0);
static KERNEL_STACK_TOP: AtomicU64 = AtomicU64::new(0);

/// Physical address of the kernel's PML4.
#[must_use]
pub fn kernel_pml4() -> u64 {
    KERNEL_PML4.load(Ordering::Relaxed)
}

/// Where everything ended up.
#[derive(Clone, Copy, Debug, Default)]
pub struct Layout {
    pub pml4: u64,
    pub kernel_virt: u64,
    pub kernel_phys: u64,
    pub text: (u64, u64),
    pub rodata: (u64, u64),
    pub data: (u64, u64),
    pub stack_top: u64,
    pub stack_guard: u64,
    pub ist_tops: [u64; 3],
    pub heap_base: u64,
    pub lapic_virt: u64,
    pub hhdm_slots: (usize, usize),
    pub slots: [usize; 3],
}

unsafe extern "C" {
    static __text_start: u8;
    static __text_end: u8;
    static __rodata_start: u8;
    static __rodata_end: u8;
    static __data_start: u8;
    static __data_end: u8;
}

fn slot_base(index: usize) -> u64 {
    let raw = (index as u64) << 39;
    if index >= 256 {
        raw | 0xffff_0000_0000_0000
    } else {
        raw
    }
}

fn map_kernel(
    pml4: u64,
    vaddr: u64,
    phys: u64,
    flags: u64,
    size: PageSize,
) -> Result<(), MapError> {
    paging::map(pml4, vaddr, phys, flags | GLOBAL, size, &mut frame::alloc)
}

/// Maps `[start, end)` of the running kernel image, translating through the
/// bootloader's page tables to find the physical frames.
fn map_image_range(pml4: u64, boot_pml4: u64, start: u64, end: u64, flags: u64) {
    let mut va = start;
    while va < end {
        let t =
            paging::translate(boot_pml4, va).expect("kernel image page not mapped by bootloader");
        map_kernel(pml4, va, t.phys, flags, PageSize::Size4K).expect("map kernel image");
        va += PAGE_SIZE;
    }
}

/// Maps `pages` fresh zeroed frames at `base` (read-write, no-execute).
fn map_fresh(pml4: u64, base: u64, pages: u64) {
    for i in 0..pages {
        let phys = frame::alloc().expect("out of memory while mapping kernel stacks");
        map_kernel(
            pml4,
            base + i * PAGE_SIZE,
            phys,
            WRITABLE | NO_EXECUTE,
            PageSize::Size4K,
        )
        .expect("map kernel stack");
    }
}

/// Builds the kernel page tables. Does **not** activate them.
pub fn build(map: &MemoryMap, lapic_phys: u64, rng: &mut ChaChaRng) -> Layout {
    let boot_pml4 = arch::read_cr3();
    let pml4 = frame::alloc().expect("out of memory for kernel PML4");
    let mut layout = Layout {
        pml4,
        ..Layout::default()
    };

    let text = (&raw const __text_start as u64, &raw const __text_end as u64);
    let rodata = (
        &raw const __rodata_start as u64,
        &raw const __rodata_end as u64,
    );
    let data = (&raw const __data_start as u64, &raw const __data_end as u64);
    // The image is physically contiguous with a single virtual-to-physical offset.
    let image_phys = paging::translate(boot_pml4, text.0)
        .expect("kernel image not mapped")
        .phys;
    let image_phys_end = image_phys + (data.1 - text.0);
    let in_image = |pa: u64| pa >= image_phys && pa < image_phys_end;

    // 1. Direct map of RAM: read-write, never executable. The kernel image's own
    //    frames are mapped read-only there, so the alias cannot be used to modify
    //    kernel code or read-only data.
    let hhdm = hhdm();
    let mut lo = usize::MAX;
    let mut hi = 0;
    for r in map.iter().filter(|r| r.kind.direct_mapped()) {
        let mut pa = r.base & !(PAGE_SIZE - 1);
        let end = (r.base + r.len).next_multiple_of(PAGE_SIZE);
        lo = lo.min(((hhdm + pa) >> 39 & 511) as usize);
        hi = hi.max(((hhdm + end - 1) >> 39 & 511) as usize);
        while pa < end {
            let use_2m = pa.is_multiple_of(SIZE_2M)
                && end - pa >= SIZE_2M
                && !(pa < image_phys_end && pa + SIZE_2M > image_phys);
            if use_2m
                && map_kernel(pml4, hhdm + pa, pa, WRITABLE | NO_EXECUTE, PageSize::Size2M).is_ok()
            {
                pa += SIZE_2M;
                continue;
            }
            // 4 KiB granularity (also the fallback when part of a 2 MiB chunk was
            // already mapped by a neighbouring region).
            let chunk_end = if use_2m { pa + SIZE_2M } else { pa + PAGE_SIZE };
            while pa < chunk_end {
                let flags = if in_image(pa) {
                    NO_EXECUTE
                } else {
                    WRITABLE | NO_EXECUTE
                };
                match map_kernel(pml4, hhdm + pa, pa, flags, PageSize::Size4K) {
                    Ok(()) | Err(MapError::AlreadyMapped | MapError::HugePageConflict) => {}
                    Err(MapError::OutOfMemory) => panic!("out of memory building the direct map"),
                }
                pa += PAGE_SIZE;
            }
        }
    }
    layout.hhdm_slots = (lo, hi);

    // 2. Kernel image with strict W^X.
    map_image_range(pml4, boot_pml4, text.0, text.1, 0);
    map_image_range(pml4, boot_pml4, rodata.0, rodata.1, NO_EXECUTE);
    map_image_range(pml4, boot_pml4, data.0, data.1, WRITABLE | NO_EXECUTE);
    layout.text = text;
    layout.rodata = rodata;
    layout.data = data;
    layout.kernel_virt = text.0;
    layout.kernel_phys = paging::translate(boot_pml4, text.0).map_or(0, |t| t.phys);
    let image_slot = (text.0 >> 39 & 511) as usize;

    // 3. Pick three distinct random top-level slots for stack, heap and MMIO.
    let mut slots = [0usize; 3];
    let mut chosen = 0;
    while chosen < 3 {
        let candidate = 256 + rng.below(255) as usize; // 256..=510
        let taken = (lo..=hi).contains(&candidate)
            || candidate == image_slot
            || slots[..chosen].contains(&candidate);
        if !taken {
            slots[chosen] = candidate;
            chosen += 1;
        }
    }
    layout.slots = slots;
    let random_offset = |rng: &mut ChaChaRng| rng.below(1 << 17) * SIZE_2M; // within 256 GiB

    // 4. Kernel stack and IST stacks, separated by unmapped guard pages:
    //    [guard][stack x16][guard][ist1 x4][guard][ist2 x4][guard][ist3 x4][guard]
    let stack_region = slot_base(slots[0]) + random_offset(rng);
    layout.stack_guard = stack_region;
    let stack_base = stack_region + PAGE_SIZE;
    map_fresh(pml4, stack_base, STACK_PAGES);
    layout.stack_top = stack_base + STACK_PAGES * PAGE_SIZE;
    let mut cursor = layout.stack_top + PAGE_SIZE;
    for top in &mut layout.ist_tops {
        map_fresh(pml4, cursor, IST_PAGES);
        *top = cursor + IST_PAGES * PAGE_SIZE;
        cursor = *top + PAGE_SIZE;
    }

    // 5. Heap: pre-create the top-level entry so that every address space created
    //    later shares the heap's page tables.
    layout.heap_base = slot_base(slots[1]) + random_offset(rng);
    let pdpt = frame::alloc().expect("out of memory for heap tables");
    paging::set_pml4_entry(pml4, slots[1], pdpt | PRESENT | WRITABLE);

    // 6. Local APIC registers, uncached.
    layout.lapic_virt = slot_base(slots[2]) + rng.below(1 << 20) * PAGE_SIZE;
    map_kernel(
        pml4,
        layout.lapic_virt,
        lapic_phys,
        WRITABLE | NO_EXECUTE | NO_CACHE | WRITE_THROUGH,
        PageSize::Size4K,
    )
    .expect("map local APIC");

    KERNEL_PML4.store(pml4, Ordering::Relaxed);
    KERNEL_STACK_TOP.store(layout.stack_top, Ordering::Relaxed);
    layout
}

/// Maps one fresh page into the heap region.
pub fn map_heap_page(vaddr: u64) -> Option<()> {
    let phys = frame::alloc()?;
    match map_kernel(
        kernel_pml4(),
        vaddr,
        phys,
        WRITABLE | NO_EXECUTE,
        PageSize::Size4K,
    ) {
        Ok(()) => Some(()),
        Err(_) => {
            frame::free(phys);
            None
        }
    }
}

/// Unmaps and frees a heap page.
pub fn unmap_heap_page(vaddr: u64) {
    if let Some(phys) = paging::unmap(kernel_pml4(), vaddr) {
        arch::invlpg(vaddr);
        frame::free(phys);
    }
}

/// Activates the page tables built by [`build`] and continues in `next` on the
/// kernel's guard-paged stack. Never returns.
pub fn enter(next: extern "C" fn() -> !) -> ! {
    let pml4 = kernel_pml4();
    let stack_top = KERNEL_STACK_TOP.load(Ordering::Relaxed);
    assert!(
        pml4 != 0 && stack_top != 0,
        "kernel address space not built"
    );
    // SAFETY: `build` created this PML4 with the kernel image, the direct map
    // (including the bootloader stack and all boot data) and the kernel stack
    // ending at `stack_top`; `next` never returns.
    unsafe { arch::entry::switch_to_kernel_space(pml4, stack_top, next) }
}
