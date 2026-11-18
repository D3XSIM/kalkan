//! User address spaces and user-memory access.
//!
//! **The kernel never dereferences a user pointer.** Instead of reading user
//! memory through user virtual addresses (which would require lifting SMAP with
//! `stac`), every access walks the target address space's page tables, checks the
//! *user-visible* permissions of each page, and copies through the kernel's
//! direct map. Consequences:
//!
//! * SMAP is never disabled — there is no `stac` instruction in the kernel;
//! * a user pointer into kernel memory or into an unmapped page is rejected with
//!   `EFAULT` — it can never cause a kernel fault;
//! * no TOCTOU window: the kernel is single threaded and non-preemptible.

use kcore::abi;

use super::paging::{self, MapError, PageSize, Translation, flags::*};
use super::{PAGE_SIZE, frame, kspace, phys_to_virt};
use crate::arch;

/// Permissions of a user mapping. W+X is unrepresentable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserPerms {
    writable: bool,
    executable: bool,
}

impl UserPerms {
    /// Read-write, non-executable.
    pub const READ_WRITE: Self = Self {
        writable: true,
        executable: false,
    };

    /// Builds permissions, refusing writable + executable.
    #[must_use]
    pub const fn new(writable: bool, executable: bool) -> Option<Self> {
        if writable && executable {
            None
        } else {
            Some(Self {
                writable,
                executable,
            })
        }
    }

    const fn leaf_flags(self) -> u64 {
        let mut f = USER;
        if self.writable {
            f |= WRITABLE;
        }
        if !self.executable {
            f |= NO_EXECUTE;
        }
        f
    }
}

/// An invalid user pointer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BadAddress;

/// Maximum number of page-table frames (below the PML4) per address space.
///
/// Together with pruning of empty tables on unmap this bounds the kernel memory a
/// process can consume through mappings, independently of its frame budget.
pub const MAX_PAGE_TABLES: u32 = 64;

/// A user address space. The lower half is private; the upper half shares the
/// kernel's page tables (supervisor-only).
#[derive(Debug)]
pub struct AddressSpace {
    pml4: u64,
    /// Page-table frames currently allocated for the user half.
    tables: u32,
}

impl AddressSpace {
    /// Creates an empty address space.
    pub fn new() -> Option<Self> {
        let pml4 = frame::alloc_user()?;
        paging::copy_kernel_half(kspace::kernel_pml4(), pml4);
        Some(Self { pml4, tables: 0 })
    }

    /// `true` if this is the address space currently loaded in CR3.
    #[must_use]
    pub fn is_active(&self) -> bool {
        arch::read_cr3() == self.pml4
    }

    /// Switches the CPU to this address space. Issues an indirect branch prediction
    /// barrier when the address space actually changes.
    pub fn activate(&self) {
        if !self.is_active() {
            arch::cpu::ibpb();
            // SAFETY: the PML4 maps the whole kernel half (copied at creation and
            // shared below the top level), so the running code, stack and data stay
            // mapped.
            unsafe { arch::write_cr3(self.pml4) };
        }
    }

    /// Maps one user page. The caller has validated `vaddr`.
    pub fn map(&mut self, vaddr: u64, phys: u64, perms: UserPerms) -> Result<(), MapError> {
        assert!(
            vaddr.is_multiple_of(PAGE_SIZE) && abi::is_user_range(vaddr, PAGE_SIZE),
            "user mapping outside user space"
        );
        let tables = &mut self.tables;
        let mut alloc_table = || {
            if *tables >= MAX_PAGE_TABLES {
                return None;
            }
            let t = frame::alloc_user()?;
            *tables += 1;
            Some(t)
        };
        paging::map(
            self.pml4,
            vaddr,
            phys,
            perms.leaf_flags(),
            PageSize::Size4K,
            &mut alloc_table,
        )
    }

    /// Unmaps one user page and returns the frame that was mapped there.
    pub fn unmap(&mut self, vaddr: u64) -> Option<u64> {
        if !abi::is_user_range(vaddr, PAGE_SIZE) {
            return None;
        }
        let tables = &mut self.tables;
        let phys = paging::unmap_user(self.pml4, vaddr, &mut |t| {
            frame::free(t);
            *tables -= 1;
        })?;
        if self.is_active() {
            // Also invalidates the paging-structure caches of the pruned tables.
            arch::invlpg(vaddr);
        }
        Some(phys)
    }

    /// Translates a user address (user-accessible pages only).
    #[must_use]
    pub fn translate(&self, vaddr: u64) -> Option<Translation> {
        if !abi::is_user_range(vaddr, 1) {
            return None;
        }
        paging::translate(self.pml4, vaddr).filter(|t| t.user)
    }

    /// Copies `dst.len()` bytes from user address `src`.
    pub fn copy_from_user(&self, src: u64, dst: &mut [u8]) -> Result<(), BadAddress> {
        self.walk(src, dst.len(), |phys, offset, len| {
            // SAFETY: `phys` is a mapped user frame inside the direct map and the
            // range stays within that frame.
            let from = unsafe { core::slice::from_raw_parts(phys_to_virt(phys) as *const u8, len) };
            dst[offset..offset + len].copy_from_slice(from);
        })
    }

    /// Writes into the image regardless of the user write permission. Only used by
    /// the program loader to apply relocations before the program runs.
    pub fn kernel_write(&self, dst: u64, src: &[u8]) -> Result<(), BadAddress> {
        self.walk(dst, src.len(), |phys, offset, len| {
            // SAFETY: as above; the loader owns the image during loading.
            let to = unsafe { core::slice::from_raw_parts_mut(phys_to_virt(phys) as *mut u8, len) };
            to.copy_from_slice(&src[offset..offset + len]);
        })
    }

    fn walk(
        &self,
        addr: u64,
        len: usize,
        mut f: impl FnMut(u64, usize, usize),
    ) -> Result<(), BadAddress> {
        if len == 0 {
            return Ok(());
        }
        if !abi::is_user_range(addr, len as u64) {
            return Err(BadAddress);
        }
        // Validate the whole range before touching anything (all-or-nothing).
        let mut va = addr & !(PAGE_SIZE - 1);
        while va < addr + len as u64 {
            self.translate(va).ok_or(BadAddress)?;
            va += PAGE_SIZE;
        }
        let mut done = 0usize;
        while done < len {
            let va = addr + done as u64;
            let in_page = (PAGE_SIZE - (va % PAGE_SIZE)) as usize;
            let chunk = in_page.min(len - done);
            let t = self.translate(va).ok_or(BadAddress)?;
            f(t.phys, done, chunk);
            done += chunk;
        }
        Ok(())
    }
}

impl Drop for AddressSpace {
    fn drop(&mut self) {
        if self.is_active() {
            // SAFETY: the kernel PML4 maps everything the kernel needs.
            unsafe { arch::write_cr3(kspace::kernel_pml4()) };
        }
        paging::free_user_tables(self.pml4);
        frame::free(self.pml4);
    }
}

/// Writes bytes into a frame through the direct map (program loading).
pub fn write_frame(phys: u64, offset: usize, bytes: &[u8]) {
    assert!(offset + bytes.len() <= PAGE_SIZE as usize);
    // SAFETY: `phys` is a frame owned by the caller and the range is inside it.
    unsafe {
        core::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            (phys_to_virt(phys) + offset as u64) as *mut u8,
            bytes.len(),
        );
    }
}
