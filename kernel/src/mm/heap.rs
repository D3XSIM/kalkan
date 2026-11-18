//! Hardened kernel heap.
//!
//! A segregated-fit allocator with eight power-of-two size classes (16 B – 2 KiB)
//! plus page-granular large allocations. Hardening:
//!
//! * **Encoded free lists** — free-list pointers are stored XOR-ed with a per-boot
//!   random secret and the block address ("safe linking"), and every decoded
//!   pointer is validated. A heap overflow can therefore not forge a free-list
//!   entry to make the allocator return an arbitrary address.
//! * **Poisoning** — freed blocks are filled with a pattern that is verified on
//!   reuse: writes after free are detected.
//! * **Double-free detection** for the common patterns.
//! * **Zeroing** — every allocation is returned zeroed.
//! * **Guard pages** — every large allocation is followed by an unmapped page.
//! * Any detected corruption panics: the kernel stops rather than continue with a
//!   corrupted heap (fail-closed).

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;

use kcore::chacha20::ChaChaRng;

use super::PAGE_SIZE;
use super::kspace::{self, HEAP_SIZE};
use crate::sync::SpinLock;

const CLASSES: [usize; 8] = [16, 32, 64, 128, 256, 512, 1024, 2048];
const POISON: u8 = 0xa5;
/// Number of freed large spans remembered for reuse.
const SPAN_CACHE: usize = 64;

struct State {
    start: u64,
    bump: u64,
    limit: u64,
    heads: [u64; CLASSES.len()],
    secret: u64,
    allocated: usize,
    /// Freed large allocations `(base, pages)`, reused so that repeated large
    /// allocations cannot exhaust the heap's virtual address range.
    spans: [(u64, u64); SPAN_CACHE],
}

static STATE: SpinLock<Option<State>> = SpinLock::new(None);

/// Initialises the heap. Must be called after the kernel page tables are active.
pub fn init(base: u64, rng: &mut ChaChaRng) {
    *STATE.lock() = Some(State {
        start: base + PAGE_SIZE, // the first page stays unmapped
        bump: base + PAGE_SIZE,
        limit: base + HEAP_SIZE,
        heads: [0; CLASSES.len()],
        secret: rng.next_u64() | 1,
        allocated: 0,
        spans: [(0, 0); SPAN_CACHE],
    });
}

/// Bytes currently allocated.
#[must_use]
pub fn allocated() -> usize {
    STATE.lock().as_ref().map_or(0, |s| s.allocated)
}

fn class_index(layout: &Layout) -> Option<usize> {
    let need = layout.size().max(layout.align()).max(16);
    CLASSES.iter().position(|&c| c >= need)
}

impl State {
    fn encode(&self, block: u64, next: u64) -> u64 {
        next ^ block.rotate_left(17) ^ self.secret
    }

    fn decode(&self, block: u64, stored: u64) -> u64 {
        stored ^ block.rotate_left(17) ^ self.secret
    }

    fn valid_block(&self, addr: u64, class: usize) -> bool {
        addr >= self.start && addr < self.bump && addr.is_multiple_of(CLASSES[class] as u64)
    }

    fn push(&mut self, class: usize, block: u64) {
        let size = CLASSES[class];
        let next = self.heads[class];
        // SAFETY: `block` is a heap block of `size` bytes owned by the allocator.
        unsafe {
            ptr::write_bytes((block + 8) as *mut u8, POISON, size - 8);
            ptr::write(block as *mut u64, self.encode(block, next));
        }
        self.heads[class] = block;
    }

    fn pop(&mut self, class: usize) -> Option<u64> {
        let block = self.heads[class];
        if block == 0 {
            return None;
        }
        if !self.valid_block(block, class) {
            panic!("heap corruption: invalid free-list head {block:#x}");
        }
        let size = CLASSES[class];
        // SAFETY: `block` is a validated free block of `size` bytes.
        let (stored, poisoned) = unsafe {
            let stored = ptr::read(block as *const u64);
            let body = core::slice::from_raw_parts((block + 8) as *const u8, size - 8);
            (stored, body.iter().all(|&b| b == POISON))
        };
        let next = self.decode(block, stored);
        if next != 0 && !self.valid_block(next, class) {
            panic!("heap corruption: forged free-list pointer in block {block:#x}");
        }
        if !poisoned {
            panic!("heap corruption: write after free detected in block {block:#x}");
        }
        self.heads[class] = next;
        Some(block)
    }

    fn grow(&mut self, class: usize) -> bool {
        if self.bump + PAGE_SIZE > self.limit || kspace::map_heap_page(self.bump).is_none() {
            return false;
        }
        let page = self.bump;
        self.bump += PAGE_SIZE;
        let size = CLASSES[class] as u64;
        // Push in reverse so blocks are handed out in address order.
        let mut offset = PAGE_SIZE - size;
        loop {
            self.push(class, page + offset);
            if offset == 0 {
                break;
            }
            offset -= size;
        }
        true
    }

    fn alloc_large(&mut self, layout: &Layout) -> u64 {
        if layout.align() > PAGE_SIZE as usize {
            return 0;
        }
        let pages = (layout.size() as u64).div_ceil(PAGE_SIZE);
        // Reuse a freed span of exactly this size (its guard page is still there).
        let recycled = self
            .spans
            .iter()
            .position(|&(base, n)| base != 0 && n == pages);
        let base = match recycled {
            Some(i) => self.spans[i].0,
            None => {
                let span = (pages + 1) * PAGE_SIZE; // + trailing guard page
                if self.bump + span > self.limit {
                    return 0;
                }
                self.bump
            }
        };
        for i in 0..pages {
            if kspace::map_heap_page(base + i * PAGE_SIZE).is_none() {
                for j in 0..i {
                    kspace::unmap_heap_page(base + j * PAGE_SIZE);
                }
                return 0;
            }
        }
        match recycled {
            Some(i) => self.spans[i] = (0, 0),
            None => self.bump += (pages + 1) * PAGE_SIZE,
        }
        base
    }

    fn free_large(&mut self, addr: u64, size: usize) {
        let pages = (size as u64).div_ceil(PAGE_SIZE);
        for i in 0..pages {
            kspace::unmap_heap_page(addr + i * PAGE_SIZE);
        }
        if let Some(slot) = self.spans.iter_mut().find(|s| s.0 == 0) {
            *slot = (addr, pages);
        }
    }
}

/// The kernel's global allocator.
struct KernelHeap;

// SAFETY: all state is behind a lock; returned blocks are exclusively owned by the
// caller until deallocated, are at least `layout.size()` bytes and are aligned to
// `layout.align()` (size classes are naturally aligned powers of two, large
// allocations are page aligned).
unsafe impl GlobalAlloc for KernelHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut guard = STATE.lock();
        let Some(state) = guard.as_mut() else {
            return ptr::null_mut();
        };
        let addr = match class_index(&layout) {
            Some(class) => {
                if state.heads[class] == 0 && !state.grow(class) {
                    return ptr::null_mut();
                }
                let Some(block) = state.pop(class) else {
                    return ptr::null_mut();
                };
                // SAFETY: the block is ours and `CLASSES[class]` bytes long.
                unsafe { ptr::write_bytes(block as *mut u8, 0, CLASSES[class]) };
                state.allocated += CLASSES[class];
                block
            }
            None => {
                let block = state.alloc_large(&layout);
                if block != 0 {
                    state.allocated += layout.size();
                }
                block
            }
        };
        addr as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let mut guard = STATE.lock();
        let state = guard.as_mut().expect("heap not initialised");
        let addr = ptr as u64;
        match class_index(&layout) {
            Some(class) => {
                if !state.valid_block(addr, class) {
                    panic!("heap: freeing invalid pointer {addr:#x}");
                }
                if state.heads[class] == addr {
                    panic!("heap: double free of {addr:#x}");
                }
                state.allocated -= CLASSES[class];
                state.push(class, addr);
            }
            None => {
                state.free_large(addr, layout.size());
                state.allocated -= layout.size();
            }
        }
    }
}

#[global_allocator]
static HEAP: KernelHeap = KernelHeap;
