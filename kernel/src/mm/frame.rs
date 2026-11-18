//! Physical frame allocator.
//!
//! Every frame is zeroed when it is **allocated** (no stale data can ever reach a
//! new owner) and again when it is **freed** (secrets do not linger in free
//! memory). Double frees are detected by the bitmap and are fatal.

use kcore::bitmap::FrameBitmap;

use super::{MemoryMap, PAGE_SIZE, RegionKind, phys_to_virt};
use crate::sync::SpinLock;

static ALLOCATOR: SpinLock<Option<FrameBitmap<'static>>> = SpinLock::new(None);
/// Physical address and length (in words) of the bitmap's storage.
static STORAGE: SpinLock<(u64, usize)> = SpinLock::new((0, 0));

fn zero(phys: u64) {
    // SAFETY: `phys` is a frame owned by the caller and covered by the direct map.
    unsafe { core::ptr::write_bytes(phys_to_virt(phys) as *mut u8, 0, PAGE_SIZE as usize) };
}

/// Initialises the allocator from the boot memory map.
///
/// The bitmap itself is carved out of the first usable region large enough.
pub fn init(map: &MemoryMap) {
    let top = map
        .iter()
        .filter(|r| r.kind == RegionKind::Usable || r.kind == RegionKind::BootloaderReclaimable)
        .map(|r| r.base + r.len)
        .max()
        .expect("no usable memory");
    let frames = top.div_ceil(PAGE_SIZE) as usize;
    let words = FrameBitmap::words_needed(frames);
    let bytes = (words * 8) as u64;
    let pages = bytes.div_ceil(PAGE_SIZE);

    let storage = map
        .iter()
        .find(|r| r.kind == RegionKind::Usable && r.base >= PAGE_SIZE && r.len >= pages * PAGE_SIZE)
        .expect("no region large enough for the frame bitmap");
    let storage_base = storage.base;

    // SAFETY: the storage pages are usable RAM (per the memory map), mapped by the
    // bootloader's direct map, and reserved below so nothing else will ever use
    // them. The slice lives for the rest of the kernel's lifetime.
    let words_slice =
        unsafe { core::slice::from_raw_parts_mut(phys_to_virt(storage_base) as *mut u64, words) };
    let mut bitmap = FrameBitmap::new(words_slice, frames).expect("bitmap storage");
    for r in map.iter().filter(|r| r.kind == RegionKind::Usable) {
        let start = r.base.div_ceil(PAGE_SIZE) as usize;
        let end = ((r.base + r.len) / PAGE_SIZE) as usize;
        if end > start {
            bitmap.release_range(start, end - start);
        }
    }
    // Never hand out physical page 0 or the bitmap's own storage.
    bitmap.reserve_range(0, 1);
    bitmap.reserve_range((storage_base / PAGE_SIZE) as usize, pages as usize);
    *ALLOCATOR.lock() = Some(bitmap);
    *STORAGE.lock() = (storage_base, words);
}

/// Re-attaches the allocator to its bitmap after the direct map of physical
/// memory has moved to a new virtual address (see `kspace::enter`).
pub fn rebase() {
    let (storage_base, words) = *STORAGE.lock();
    let mut guard = ALLOCATOR.lock();
    let bitmap = guard.take().expect("frame allocator not initialised");
    // SAFETY: the same storage pages as in `init`, now reachable through the new
    // direct map. The old slice inside `bitmap` is dropped without being used.
    let words_slice =
        unsafe { core::slice::from_raw_parts_mut(phys_to_virt(storage_base) as *mut u64, words) };
    *guard = Some(bitmap.with_storage(words_slice).expect("bitmap storage"));
}

/// Releases bootloader-reclaimable memory once nothing references it any more.
/// The memory is zeroed first, erasing any data the bootloader left behind.
pub fn reclaim_bootloader_memory(map: &MemoryMap) -> u64 {
    let mut guard = ALLOCATOR.lock();
    let bitmap = guard.as_mut().expect("frame allocator not initialised");
    let mut reclaimed = 0;
    for r in map
        .iter()
        .filter(|r| r.kind == RegionKind::BootloaderReclaimable)
    {
        let start = r.base.div_ceil(PAGE_SIZE).max(1);
        let end = ((r.base + r.len) / PAGE_SIZE).min(bitmap.frames() as u64);
        for frame in start..end {
            zero(frame * PAGE_SIZE);
        }
        if end > start {
            bitmap.release_range(start as usize, (end - start) as usize);
            reclaimed += end - start;
        }
    }
    bitmap.reserve_range(0, 1);
    reclaimed
}

/// Frames that only the kernel itself may use (heap growth, kernel tables). User
/// activity — new objects, user page tables, program images — can never push free
/// memory below this, so it can never make a kernel allocation fail.
pub const KERNEL_RESERVE: usize = 1024;

/// Allocates one zeroed frame for the kernel's own use.
pub fn alloc() -> Option<u64> {
    let frame = ALLOCATOR.lock().as_mut()?.alloc()?;
    let phys = frame as u64 * PAGE_SIZE;
    zero(phys);
    Some(phys)
}

/// Allocates one zeroed frame on behalf of user space (respects the reserve).
pub fn alloc_user() -> Option<u64> {
    let frame = {
        let mut guard = ALLOCATOR.lock();
        let bitmap = guard.as_mut()?;
        if bitmap.free_frames() <= KERNEL_RESERVE {
            return None;
        }
        bitmap.alloc()?
    };
    let phys = frame as u64 * PAGE_SIZE;
    zero(phys);
    Some(phys)
}

/// Zeroes and frees a frame.
pub fn free(phys: u64) {
    assert!(
        phys.is_multiple_of(PAGE_SIZE),
        "freeing unaligned frame {phys:#x}"
    );
    zero(phys);
    let mut guard = ALLOCATOR.lock();
    let bitmap = guard.as_mut().expect("frame allocator not initialised");
    if let Err(e) = bitmap.free((phys / PAGE_SIZE) as usize) {
        panic!("frame allocator: {e:?} for frame {phys:#x}");
    }
}

/// `(free, total)` frame counts.
#[must_use]
pub fn stats() -> (usize, usize) {
    ALLOCATOR
        .lock()
        .as_ref()
        .map_or((0, 0), |b| (b.free_frames(), b.frames()))
}
