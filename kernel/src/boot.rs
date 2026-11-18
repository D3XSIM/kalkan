//! Limine boot protocol (base revision 6), implemented without third-party crates.
//!
//! Only the handful of requests the kernel needs are declared. Every response is
//! copied into kernel-owned memory early, so bootloader memory can be reclaimed
//! (and zeroed) before user space starts.

use core::arch::naked_asm;
use core::cell::UnsafeCell;
use core::ptr;

use crate::mm::{MemoryMap, Region, RegionKind};

const COMMON_MAGIC: [u64; 2] = [0xc7b1_dd30_df4c_8b88, 0x0a82_e883_a194_f07b];
const BASE_REVISION_MAGIC: [u64; 2] = [0xf956_2b2d_5c95_a6c8, 0x6a7b_3849_4453_6bdc];
const REQUESTED_REVISION: u64 = 6;

const fn id(a: u64, b: u64) -> [u64; 4] {
    [COMMON_MAGIC[0], COMMON_MAGIC[1], a, b]
}

#[repr(C)]
struct Request<R> {
    id: [u64; 4],
    revision: u64,
    response: UnsafeCell<*const R>,
}

// SAFETY: requests are written once by the bootloader before the kernel starts and
// only read afterwards (volatile, on a single CPU).
unsafe impl<R> Sync for Request<R> {}

impl<R> Request<R> {
    const fn new(id: [u64; 4]) -> Self {
        Self {
            id,
            revision: 0,
            response: UnsafeCell::new(ptr::null()),
        }
    }

    fn response(&self) -> Option<&'static R> {
        // SAFETY: the bootloader either left the pointer null or pointed it at a
        // valid response structure that stays mapped until we reclaim bootloader
        // memory, which happens only after all responses have been consumed.
        unsafe {
            let p = ptr::read_volatile(self.response.get());
            p.as_ref()
        }
    }
}

#[repr(C)]
struct BaseRevision(UnsafeCell<[u64; 3]>);
// SAFETY: as for `Request`.
unsafe impl Sync for BaseRevision {}

#[repr(C)]
pub struct HhdmResponse {
    revision: u64,
    offset: u64,
}

#[repr(C)]
struct MemmapEntry {
    base: u64,
    length: u64,
    kind: u64,
}

#[repr(C)]
pub struct MemmapResponse {
    revision: u64,
    entry_count: u64,
    entries: *const *const MemmapEntry,
}

#[repr(C)]
pub struct ExecutableAddressResponse {
    revision: u64,
    physical_base: u64,
    virtual_base: u64,
}

#[repr(C)]
struct File {
    revision: u64,
    address: *const u8,
    size: u64,
    path: *const u8,
    string: *const u8,
}

#[repr(C)]
pub struct ModuleResponse {
    revision: u64,
    module_count: u64,
    modules: *const *const File,
}

#[repr(C)]
pub struct BootloaderInfoResponse {
    revision: u64,
    name: *const u8,
    version: *const u8,
}

#[used]
#[unsafe(link_section = ".limine_requests_start")]
static REQUESTS_START: [u64; 4] = [
    0xf6b8_f4b3_9de7_d1ae,
    0xfab9_1a69_40fc_b9cf,
    0x785c_6ed0_15d3_e316,
    0x181e_920a_7852_b9d9,
];

#[used]
#[unsafe(link_section = ".limine_requests")]
static BASE_REVISION: BaseRevision = BaseRevision(UnsafeCell::new([
    BASE_REVISION_MAGIC[0],
    BASE_REVISION_MAGIC[1],
    REQUESTED_REVISION,
]));

#[used]
#[unsafe(link_section = ".limine_requests")]
static HHDM: Request<HhdmResponse> = Request::new(id(0x48dc_f1cb_8ad2_b852, 0x6398_4e95_9a98_244b));

#[used]
#[unsafe(link_section = ".limine_requests")]
static MEMMAP: Request<MemmapResponse> =
    Request::new(id(0x67cf_3d9d_378a_806f, 0xe304_acdf_c50c_3c62));

#[used]
#[unsafe(link_section = ".limine_requests")]
static EXECUTABLE_ADDRESS: Request<ExecutableAddressResponse> =
    Request::new(id(0x71ba_7686_3cc5_5f63, 0xb264_4a48_c516_a487));

#[used]
#[unsafe(link_section = ".limine_requests")]
static MODULES: Request<ModuleResponse> =
    Request::new(id(0x3e7e_2797_02be_32af, 0xca1c_4f3b_d128_0cee));

#[used]
#[unsafe(link_section = ".limine_requests")]
static BOOTLOADER_INFO: Request<BootloaderInfoResponse> =
    Request::new(id(0xf550_38d8_e2a1_202f, 0x2794_26fc_f5f5_9740));

#[used]
#[unsafe(link_section = ".limine_requests_end")]
static REQUESTS_END: [u64; 2] = [0xadc0_e053_1bb1_0d03, 0x9572_709f_3176_4c62];

/// Kernel entry point (jumped to by Limine).
///
/// Aligns the stack as the System V ABI expects and calls into Rust.
#[unsafe(naked)]
#[unsafe(no_mangle)]
extern "C" fn kalkan_entry() -> ! {
    naked_asm!(
        "and rsp, -16",
        "xor ebp, ebp",
        "call {main}",
        "ud2",
        main = sym crate::boot_main,
    )
}

/// `true` if the bootloader honoured the requested base revision.
#[must_use]
pub fn base_revision_supported() -> bool {
    // SAFETY: written by the bootloader before entry; read-only afterwards.
    unsafe { ptr::read_volatile(BASE_REVISION.0.get())[2] == 0 }
}

/// Offset of the higher-half direct map.
#[must_use]
pub fn hhdm_offset() -> Option<u64> {
    HHDM.response().map(|r| r.offset)
}

/// Physical and virtual load address of the kernel image (KASLR).
#[must_use]
pub fn kernel_address() -> Option<(u64, u64)> {
    EXECUTABLE_ADDRESS
        .response()
        .map(|r| (r.physical_base, r.virtual_base))
}

fn cstr(p: *const u8) -> &'static str {
    if p.is_null() {
        return "";
    }
    // SAFETY: Limine strings are NUL-terminated and live in bootloader memory that
    // is only reclaimed after the kernel stopped using them.
    let bytes = unsafe { core::ffi::CStr::from_ptr(p.cast()) }.to_bytes();
    core::str::from_utf8(bytes).unwrap_or("?")
}

/// Bootloader name and version.
#[must_use]
pub fn bootloader() -> (&'static str, &'static str) {
    BOOTLOADER_INFO
        .response()
        .map_or(("unknown", ""), |r| (cstr(r.name), cstr(r.version)))
}

/// Copies the memory map into kernel memory.
#[must_use]
pub fn memory_map() -> MemoryMap {
    let mut map = MemoryMap::new();
    let Some(resp) = MEMMAP.response() else {
        return map;
    };
    for i in 0..resp.entry_count as usize {
        // SAFETY: `entries` is an array of `entry_count` valid pointers.
        let e = unsafe { &**resp.entries.add(i) };
        let kind = match e.kind {
            0 => RegionKind::Usable,
            5 => RegionKind::BootloaderReclaimable,
            6 => RegionKind::KernelAndModules,
            7 => RegionKind::Framebuffer,
            _ => RegionKind::Reserved,
        };
        map.push(Region {
            base: e.base,
            len: e.length,
            kind,
        });
    }
    map
}

/// The boot modules (user-space program images), recorded as *physical* ranges.
///
/// The bootloader hands out pointers into its own direct map, which the kernel
/// replaces with a randomly placed one. Physical ranges stay valid across that
/// switch; names are matched against the expected set while the bootloader's
/// strings are still readable.
#[derive(Clone, Copy, Debug)]
pub struct Modules {
    /// `(index into the expected names, physical address, length)`.
    known: [Option<(u64, usize)>; Self::MAX_KNOWN],
    /// Number of modules the bootloader loaded, including unexpected ones.
    pub total: usize,
}

impl Modules {
    const MAX_KNOWN: usize = 4;

    /// Records every boot module. `expected` lists the module names the kernel
    /// knows. Must be called while the bootloader's direct map is still active.
    #[must_use]
    pub fn capture(expected: &[&str]) -> Self {
        let mut modules = Self {
            known: [None; Self::MAX_KNOWN],
            total: 0,
        };
        let Some(resp) = MODULES.response() else {
            return modules;
        };
        let hhdm = crate::mm::hhdm();
        for i in 0..resp.module_count as usize {
            // SAFETY: `modules` is an array of `module_count` valid `File` pointers.
            let file = unsafe { &**resp.modules.add(i) };
            modules.total += 1;
            let path = cstr(file.path);
            let name = path.rsplit('/').next().unwrap_or(path);
            let index = expected
                .iter()
                .take(Self::MAX_KNOWN)
                .position(|e| *e == name);
            let phys = (file.address as u64).checked_sub(hhdm);
            if let (Some(index), Some(phys)) = (index, phys)
                && modules.known[index].is_none()
            {
                modules.known[index] = Some((phys, file.size as usize));
            }
        }
        modules
    }

    /// The contents of the module with the given index in the expected names.
    #[must_use]
    pub fn data(&self, index: usize) -> Option<&'static [u8]> {
        let (phys, len) = (*self.known.get(index)?)?;
        // SAFETY: the module occupies `len` bytes at `phys` in memory of type
        // EXECUTABLE_AND_MODULES, which the kernel never reclaims or writes to and
        // which is covered by whichever direct map is currently active.
        Some(unsafe {
            core::slice::from_raw_parts(crate::mm::phys_to_virt(phys) as *const u8, len)
        })
    }
}

/// Keeps the marker statics referenced so the linker cannot drop them.
pub fn touch_markers() -> usize {
    REQUESTS_START.len() + REQUESTS_END.len()
}
