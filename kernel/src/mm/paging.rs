//! x86-64 4-level page tables, accessed through the direct map.

use super::{frame, phys_to_virt};

/// Allocator for page-table frames (lets user mappings be accounted separately).
pub type TableAlloc<'a> = &'a mut dyn FnMut() -> Option<u64>;

/// Page table entry flags.
pub mod flags {
    pub const PRESENT: u64 = 1 << 0;
    pub const WRITABLE: u64 = 1 << 1;
    pub const USER: u64 = 1 << 2;
    pub const WRITE_THROUGH: u64 = 1 << 3;
    pub const NO_CACHE: u64 = 1 << 4;
    pub const HUGE: u64 = 1 << 7;
    pub const GLOBAL: u64 = 1 << 8;
    pub const NO_EXECUTE: u64 = 1 << 63;
}

use flags::*;

/// Physical address bits of an entry.
pub const ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;

/// Errors from [`map`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapError {
    OutOfMemory,
    AlreadyMapped,
    HugePageConflict,
}

/// Mapping granularity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageSize {
    Size4K,
    Size2M,
}

fn table(phys: u64) -> *mut [u64; 512] {
    phys_to_virt(phys) as *mut [u64; 512]
}

const fn index(vaddr: u64, level: u32) -> usize {
    ((vaddr >> (12 + 9 * level)) & 511) as usize
}

/// Reads the entry at `level` for `vaddr` in table `table_phys`.
fn read_entry(table_phys: u64, vaddr: u64, level: u32) -> u64 {
    // SAFETY: `table_phys` is a page table frame reachable through the direct map;
    // the index is < 512.
    unsafe { (*table(table_phys))[index(vaddr, level)] }
}

fn write_entry(table_phys: u64, vaddr: u64, level: u32, value: u64) {
    // SAFETY: as above. Page tables are only modified by the kernel, which is
    // single threaded and never interrupted.
    unsafe { (*table(table_phys))[index(vaddr, level)] = value };
}

/// Walks down to the table at `target_level`, creating missing intermediate tables
/// with `table_flags`, allocated through `alloc_table`.
fn walk_create(
    pml4: u64,
    vaddr: u64,
    target_level: u32,
    table_flags: u64,
    alloc_table: TableAlloc<'_>,
) -> Result<u64, MapError> {
    let mut current = pml4;
    let mut level = 3;
    while level > target_level {
        let entry = read_entry(current, vaddr, level);
        current = if entry & PRESENT == 0 {
            let new = alloc_table().ok_or(MapError::OutOfMemory)?;
            write_entry(current, vaddr, level, new | table_flags);
            new
        } else if entry & HUGE != 0 {
            return Err(MapError::HugePageConflict);
        } else {
            entry & ADDR_MASK
        };
        level -= 1;
    }
    Ok(current)
}

/// Maps one page.
///
/// Intermediate tables are created with `PRESENT | WRITABLE` (+`USER` if the leaf
/// is a user mapping): the effective permissions are always decided by the leaf.
pub fn map(
    pml4: u64,
    vaddr: u64,
    phys: u64,
    leaf_flags: u64,
    size: PageSize,
    alloc_table: TableAlloc<'_>,
) -> Result<(), MapError> {
    let table_flags = PRESENT | WRITABLE | (leaf_flags & USER);
    let (level, extra) = match size {
        PageSize::Size4K => (0, 0),
        PageSize::Size2M => (1, HUGE),
    };
    let t = walk_create(pml4, vaddr, level, table_flags, alloc_table)?;
    if read_entry(t, vaddr, level) & PRESENT != 0 {
        return Err(MapError::AlreadyMapped);
    }
    write_entry(
        t,
        vaddr,
        level,
        (phys & ADDR_MASK) | leaf_flags | extra | PRESENT,
    );
    Ok(())
}

/// Removes a 4 KiB mapping, returning the physical frame it pointed to.
/// The caller is responsible for TLB invalidation.
pub fn unmap(pml4: u64, vaddr: u64) -> Option<u64> {
    let mut current = pml4;
    for level in (1..=3).rev() {
        let entry = read_entry(current, vaddr, level);
        if entry & PRESENT == 0 || entry & HUGE != 0 {
            return None;
        }
        current = entry & ADDR_MASK;
    }
    let entry = read_entry(current, vaddr, 0);
    if entry & PRESENT == 0 {
        return None;
    }
    write_entry(current, vaddr, 0, 0);
    Some(entry & ADDR_MASK)
}

fn table_is_empty(table_phys: u64) -> bool {
    // SAFETY: valid table frame in the direct map.
    unsafe { (*table(table_phys)).iter().all(|&e| e & PRESENT == 0) }
}

/// Frees every *empty* page table on the path to the user address `vaddr`,
/// bottom-up (including the top-level entry, which is always in the private user
/// half). Without this, mapping and unmapping at ever new addresses — or failed
/// mappings — would leave page tables behind without bound.
pub fn prune_user(pml4: u64, vaddr: u64, free_table: &mut dyn FnMut(u64)) {
    debug_assert!(index(vaddr, 3) < 256, "not a user address");
    // tables[level] is the table *at* `level` on the path to `vaddr`.
    let mut tables = [0u64; 4];
    tables[3] = pml4;
    let mut lowest = 3usize;
    for level in (1..=3u32).rev() {
        let entry = read_entry(tables[level as usize], vaddr, level);
        if entry & PRESENT == 0 || entry & HUGE != 0 {
            break;
        }
        lowest = level as usize - 1;
        tables[lowest] = entry & ADDR_MASK;
    }
    for level in lowest..3 {
        let t = tables[level];
        if !table_is_empty(t) {
            break;
        }
        write_entry(tables[level + 1], vaddr, level as u32 + 1, 0);
        free_table(t);
    }
}

/// Removes a 4 KiB **user** mapping and prunes the page tables that became empty.
/// Returns the frame that was mapped. The caller invalidates the TLB.
pub fn unmap_user(pml4: u64, vaddr: u64, free_table: &mut dyn FnMut(u64)) -> Option<u64> {
    let mut current = pml4;
    for level in (1..=3).rev() {
        let entry = read_entry(current, vaddr, level);
        if entry & PRESENT == 0 || entry & HUGE != 0 {
            return None;
        }
        current = entry & ADDR_MASK;
    }
    let leaf = read_entry(current, vaddr, 0);
    if leaf & PRESENT == 0 {
        return None;
    }
    write_entry(current, vaddr, 0, 0);
    prune_user(pml4, vaddr, free_table);
    Some(leaf & ADDR_MASK)
}

/// Result of a translation: the physical address and the *effective* permissions
/// (combined over all levels, as the MMU computes them).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Translation {
    pub phys: u64,
    pub writable: bool,
    pub user: bool,
    pub executable: bool,
    pub global: bool,
}

/// Translates a virtual address.
#[must_use]
pub fn translate(pml4: u64, vaddr: u64) -> Option<Translation> {
    let mut current = pml4;
    let mut writable = true;
    let mut user = true;
    let mut executable = true;
    for level in (0..=3).rev() {
        let entry = read_entry(current, vaddr, level);
        if entry & PRESENT == 0 {
            return None;
        }
        writable &= entry & WRITABLE != 0;
        user &= entry & USER != 0;
        executable &= entry & NO_EXECUTE == 0;
        let leaf = level == 0 || (entry & HUGE != 0 && level <= 2);
        if leaf {
            let page_mask = (1u64 << (12 + 9 * level)) - 1;
            return Some(Translation {
                phys: (entry & ADDR_MASK & !page_mask) | (vaddr & page_mask),
                writable,
                user,
                executable,
                global: entry & GLOBAL != 0,
            });
        }
        current = entry & ADDR_MASK;
    }
    None
}

/// Copies the kernel half (PML4 entries 256..512) from `src` into `dst`.
pub fn copy_kernel_half(src: u64, dst: u64) {
    // SAFETY: both are valid PML4 frames reachable through the direct map; they
    // are distinct frames so the borrows do not overlap.
    unsafe {
        let s = &*table(src);
        let d = &mut *table(dst);
        d[256..].copy_from_slice(&s[256..]);
    }
}

/// Reads a raw PML4 entry (used by the boot-time security self check).
#[must_use]
pub fn pml4_entry(pml4: u64, index: usize) -> u64 {
    // SAFETY: `pml4` is a valid table; `index` is bounds checked by the array.
    unsafe { (*table(pml4))[index & 511] }
}

/// Sets a raw PML4 entry.
pub fn set_pml4_entry(pml4: u64, index: usize, value: u64) {
    // SAFETY: as above.
    unsafe { (*table(pml4))[index & 511] = value };
}

/// Visits every present leaf entry of the *user half* of an address space as
/// `(virtual address, entry)` and returns the number of page-table frames below
/// the PML4. Used by the kernel's self-audit.
pub fn walk_user(pml4: u64, leaf: &mut dyn FnMut(u64, u64)) -> u32 {
    fn walk(table_phys: u64, level: u32, base: u64, leaf: &mut dyn FnMut(u64, u64)) -> u32 {
        let mut tables = 0;
        for i in 0..512u64 {
            // SAFETY: valid table frame in the direct map; `i` < 512.
            let entry = unsafe { (*table(table_phys))[i as usize] };
            if entry & PRESENT == 0 {
                continue;
            }
            let va = base | (i << (12 + 9 * level));
            if level == 0 || entry & HUGE != 0 {
                leaf(va, entry);
            } else {
                tables += 1 + walk(entry & ADDR_MASK, level - 1, va, leaf);
            }
        }
        tables
    }
    let mut tables = 0;
    for i in 0..256 {
        let entry = pml4_entry(pml4, i);
        if entry & PRESENT != 0 {
            tables += 1 + walk(entry & ADDR_MASK, 2, (i as u64) << 39, leaf);
        }
    }
    tables
}

/// Frees every page table frame of the *user half* of an address space (the
/// tables only; leaf frames belong to their owners).
pub fn free_user_tables(pml4: u64) {
    fn free_level(table_phys: u64, level: u32) {
        for i in 0..512 {
            // SAFETY: valid table frame in the direct map.
            let entry = unsafe { (*table(table_phys))[i] };
            if entry & PRESENT != 0 && entry & HUGE == 0 && level > 0 {
                let next = entry & ADDR_MASK;
                free_level(next, level - 1);
                frame::free(next);
            }
        }
    }
    for i in 0..256 {
        let entry = pml4_entry(pml4, i);
        if entry & PRESENT != 0 {
            let pdpt = entry & ADDR_MASK;
            free_level(pdpt, 2);
            frame::free(pdpt);
        }
    }
}
