//! Program loader.
//!
//! Turns a validated ELF image into a new process: a fresh address space with the
//! image at a **random base address** (ASLR), W^X page permissions taken from the
//! segments, relocations applied by the kernel *before* the program runs, and a
//! non-executable stack at a random address with an unmapped guard page below it.

use alloc::string::String;
use alloc::vec::Vec;

use kcore::abi;
use kcore::elf::{self, Image, Limits};

use super::Kernel;
use super::object::*;
use crate::arch::entry::TrapFrame;
use crate::mm::user::{AddressSpace, UserPerms, write_frame};
use crate::mm::{PAGE_SIZE, frame};

/// Region in which position independent images are placed (1 TiB above 64 GiB).
const IMAGE_REGION: (u64, u64) = (0x0000_0010_0000_0000, 0x0000_0110_0000_0000);
/// Region for the initial stack.
const STACK_REGION: (u64, u64) = (0x0000_7000_0000_0000, 0x0000_7f00_0000_0000);
const STACK_PAGES: u64 = 16;

/// Why a program could not be loaded.
#[derive(Debug)]
pub enum LoadError {
    Elf(#[allow(dead_code)] elf::ElfError),
    OutOfMemory,
    BadLayout,
    Limit,
}

/// A newly created process.
#[derive(Clone, Copy, Debug)]
pub struct Spawned {
    pub thread: ThreadId,
    pub vspace: VSpaceId,
}

/// A random page-aligned address `a` with `[a, a + span)` inside `[lo, hi)`.
fn random_page_in(k: &mut Kernel, lo: u64, hi: u64, span: u64) -> Option<u64> {
    let slots = (hi - lo).checked_sub(span)? / PAGE_SIZE;
    (slots > 0).then(|| lo + k.rng.below(slots) * PAGE_SIZE)
}

fn load_segments(
    space: &mut AddressSpace,
    image: &Image,
    file: &[u8],
    base: u64,
    owned: &mut Vec<u64>,
) -> Result<(), LoadError> {
    for seg in &image.segments {
        let perms = UserPerms::new(seg.perms.write, seg.perms.exec).ok_or(LoadError::BadLayout)?;
        let mut page = seg.page_start();
        while page < seg.page_end() {
            let phys = frame::alloc_user().ok_or(LoadError::OutOfMemory)?;
            owned.push(phys);
            // Copy the part of the segment's file data that falls into this page.
            let data_start = seg.vaddr.max(page);
            let data_end = (seg.vaddr + seg.file_size).min(page + PAGE_SIZE);
            if data_end > data_start {
                let off = (seg.file_offset + (data_start - seg.vaddr)) as usize;
                let len = (data_end - data_start) as usize;
                let bytes = file.get(off..off + len).ok_or(LoadError::BadLayout)?;
                write_frame(phys, (data_start - page) as usize, bytes);
            }
            space
                .map(base + page, phys, perms)
                .map_err(|_| LoadError::BadLayout)?;
            page += PAGE_SIZE;
        }
    }
    Ok(())
}

/// Loads `file` as a new, inactive process named `name`.
pub fn spawn(k: &mut Kernel, name: &str, file: &[u8]) -> Result<Spawned, LoadError> {
    let image = elf::parse(file, &Limits::default()).map_err(LoadError::Elf)?;
    let span = image.span_end - image.span_start;
    // All arithmetic on image-controlled values is checked: a malformed image is
    // rejected, it can never overflow kernel computations.
    let base = if image.relocatable {
        random_page_in(k, IMAGE_REGION.0, IMAGE_REGION.1, span)
            .and_then(|start| start.checked_sub(image.span_start))
            .ok_or(LoadError::BadLayout)?
    } else {
        0
    };
    let start = base
        .checked_add(image.span_start)
        .ok_or(LoadError::BadLayout)?;
    if !abi::is_user_range(start, span) || base.checked_add(image.entry).is_none() {
        return Err(LoadError::BadLayout);
    }

    let mut space = AddressSpace::new().ok_or(LoadError::OutOfMemory)?;
    let mut owned = Vec::new();
    let result = load_segments(&mut space, &image, file, base, &mut owned).and_then(|()| {
        for r in &image.relocations {
            let value = base.wrapping_add(r.addend);
            space
                .kernel_write(base + r.offset, &value.to_le_bytes())
                .map_err(|_| LoadError::BadLayout)?;
        }
        Ok(())
    });

    // Stack: random top, `STACK_PAGES` pages, unmapped guard page below.
    let stack_top =
        random_page_in(k, STACK_REGION.0, STACK_REGION.1, 0).ok_or(LoadError::BadLayout)?;
    let result = result.and_then(|()| {
        for i in 1..=STACK_PAGES {
            let phys = frame::alloc_user().ok_or(LoadError::OutOfMemory)?;
            owned.push(phys);
            space
                .map(stack_top - i * PAGE_SIZE, phys, UserPerms::READ_WRITE)
                .map_err(|_| LoadError::BadLayout)?;
        }
        Ok(())
    });

    let vspace = VSpace {
        space,
        owned_frames: owned,
        refs: 1,
    };
    // On error, dropping `vspace` frees every frame and page table allocated so far.
    result?;
    let vspace = k.vspaces.insert(vspace).map_err(|_| LoadError::Limit)?;
    let cspace = match k.caps.create_space(abi::CSPACE_SLOTS) {
        Ok(c) => c,
        Err(_) => {
            k.vspaces.remove(vspace);
            return Err(LoadError::Limit);
        }
    };
    let entry = base + image.entry;
    let thread = Thread {
        name: String::from(name),
        // rsp = top - 8: the ABI expects (rsp + 8) to be 16-byte aligned at entry.
        ctx: TrapFrame::new_user(entry, stack_top - 8, 0),
        state: ThreadState::Inactive,
        cspace,
        vspace,
        fault_ep: None,
        reply_to: None,
        outgoing: Outgoing::default(),
        recv_slot: None,
    };
    let thread = match k.threads.insert(thread) {
        Ok(t) => t,
        Err(_) => {
            let _ = k.caps.destroy_space(cspace);
            k.vspaces.remove(vspace);
            return Err(LoadError::Limit);
        }
    };
    crate::kprintln!(
        "[loader] '{}': {} segments, {} relocations, base {:#x}, entry {:#x}, stack top {:#x}",
        name,
        image.segments.len(),
        image.relocations.len(),
        base,
        entry,
        stack_top
    );
    Ok(Spawned { thread, vspace })
}
