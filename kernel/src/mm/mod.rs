//! Memory management.
//!
//! * [`frame`]  — physical frame allocator (zero-on-alloc *and* zero-on-free).
//! * [`paging`] — x86-64 page table manipulation.
//! * [`kspace`] — the kernel address space: strict W^X, non-executable direct map,
//!   guard-paged stacks, randomised region placement.
//! * [`heap`]   — hardened kernel heap (encoded free lists, poisoning, guard pages).
//! * [`user`]   — user address spaces and the user-memory copy routines.

pub mod frame;
pub mod heap;
pub mod kspace;
pub mod paging;
pub mod user;

use core::sync::atomic::{AtomicU64, Ordering};

/// Page size.
pub const PAGE_SIZE: u64 = 4096;

static HHDM: AtomicU64 = AtomicU64::new(0);

/// Records the offset of the higher-half direct map provided by the bootloader.
pub fn set_hhdm(offset: u64) {
    HHDM.store(offset, Ordering::Relaxed);
}

/// Offset of the direct map of physical memory.
#[must_use]
pub fn hhdm() -> u64 {
    HHDM.load(Ordering::Relaxed)
}

/// Virtual address of a physical address in the direct map.
#[must_use]
pub fn phys_to_virt(phys: u64) -> u64 {
    hhdm() + phys
}

/// A physical memory region from the boot memory map.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Region {
    pub base: u64,
    pub len: u64,
    pub kind: RegionKind,
}

/// Memory map region types (subset of the Limine types that matter here).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RegionKind {
    Usable,
    BootloaderReclaimable,
    KernelAndModules,
    Framebuffer,
    #[default]
    Reserved,
}

impl RegionKind {
    /// Regions that must be reachable through the direct map.
    #[must_use]
    pub const fn direct_mapped(self) -> bool {
        matches!(
            self,
            Self::Usable | Self::BootloaderReclaimable | Self::KernelAndModules
        )
    }
}

/// Fixed-capacity copy of the boot memory map (no heap needed).
#[derive(Clone, Copy, Debug)]
pub struct MemoryMap {
    pub regions: [Region; 128],
    pub len: usize,
}

impl MemoryMap {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            regions: [Region {
                base: 0,
                len: 0,
                kind: RegionKind::Reserved,
            }; 128],
            len: 0,
        }
    }

    pub fn push(&mut self, r: Region) {
        if self.len < self.regions.len() {
            self.regions[self.len] = r;
            self.len += 1;
        }
    }

    pub fn iter(&self) -> core::slice::Iter<'_, Region> {
        self.regions[..self.len].iter()
    }
}

impl Default for MemoryMap {
    fn default() -> Self {
        Self::new()
    }
}
