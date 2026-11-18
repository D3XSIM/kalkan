//! Strict ELF64 validator for user-space images.
//!
//! The kernel never trusts an executable. Before a single byte of a program is
//! copied into memory, [`parse`] checks every header field it relies on, using only
//! checked arithmetic and bounds-checked slice access, so that a malformed or
//! malicious file is *rejected* — it can never make the kernel panic, overflow an
//! integer or read out of bounds (this property is fuzzed, see `fuzz/`).
//!
//! In addition to structural validity, the loader enforces security policy:
//!
//! * **W^X** — no segment may be both writable and executable, and no two segments
//!   may share a page (which would force one page to carry both permissions).
//! * **Non-executable stack** — a `PT_GNU_STACK` header requesting `X` is refused.
//! * **No dynamic linking, no interpreter, no TLS, no text relocations.**
//! * **Only `R_X86_64_RELATIVE` relocations**, each fully inside a loaded segment.
//!   Position independent executables get a randomised load address (ASLR).

use alloc::vec::Vec;

const PAGE: u64 = 4096;

const PT_NULL: u32 = 0;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_NOTE: u32 = 4;
const PT_PHDR: u32 = 6;
const PT_TLS: u32 = 7;
const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PT_GNU_RELRO: u32 = 0x6474_e552;
const PT_GNU_PROPERTY: u32 = 0x6474_e553;

const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const DT_PLTRELSZ: u64 = 2;
const DT_RELA: u64 = 7;
const DT_RELASZ: u64 = 8;
const DT_RELAENT: u64 = 9;
const DT_RELSZ: u64 = 18;
const DT_TEXTREL: u64 = 22;
const DT_FLAGS: u64 = 30;
const DT_RELRSZ: u64 = 35;
const DF_TEXTREL: u64 = 0x4;

const R_X86_64_NONE: u32 = 0;
const R_X86_64_RELATIVE: u32 = 8;

const EHDR_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;
const DYN_SIZE: usize = 16;
const RELA_SIZE: usize = 24;
const MAX_DYN_ENTRIES: usize = 1024;

/// Why an image was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElfError {
    /// File shorter than a header it must contain.
    Truncated,
    /// Not an ELF file.
    BadMagic,
    /// Not ELF64 / little endian / version 1.
    UnsupportedFormat,
    /// Not an x86-64 executable.
    WrongMachine,
    /// Neither `ET_EXEC` nor `ET_DYN`.
    WrongType,
    /// Malformed header field (sizes, counts).
    BadHeader,
    /// Too many program headers or segments.
    TooManySegments,
    /// A segment's file data lies outside the file.
    SegmentOutOfFile,
    /// Address arithmetic would overflow, or `filesz > memsz`.
    BadSegment,
    /// `p_vaddr` and `p_offset` are not congruent modulo the alignment.
    Misaligned,
    /// A segment is both writable and executable (W^X).
    WriteExecSegment,
    /// Two segments overlap or share a page.
    OverlappingSegments,
    /// No `PT_LOAD` segments.
    NoLoadableSegments,
    /// The entry point is not inside an executable segment.
    EntryNotExecutable,
    /// `PT_GNU_STACK` requested an executable stack.
    ExecutableStack,
    /// `PT_INTERP`: dynamic loaders are not supported.
    Interpreter,
    /// `PT_TLS`: thread-local storage is not supported.
    Tls,
    /// Unknown program header type.
    UnknownSegment,
    /// Malformed `PT_DYNAMIC`.
    BadDynamic,
    /// Shared library dependencies (`DT_NEEDED`).
    DynamicLinking,
    /// Text relocations would require writable code.
    TextRelocations,
    /// Relocation type other than `R_X86_64_RELATIVE`.
    UnsupportedRelocation,
    /// Relocation target outside every loaded segment.
    RelocationOutOfBounds,
    /// Too many relocations.
    TooManyRelocations,
    /// The image spans more address space than allowed.
    ImageTooLarge,
}

/// Memory permissions of a segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Perms {
    /// Readable.
    pub read: bool,
    /// Writable.
    pub write: bool,
    /// Executable.
    pub exec: bool,
}

/// A validated `PT_LOAD` segment. Addresses are relative to the load base for
/// position independent images.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    /// Virtual address of the first byte.
    pub vaddr: u64,
    /// Size in memory (`>= file_size`; the remainder is zero-filled).
    pub mem_size: u64,
    /// Offset of the segment's data in the file.
    pub file_offset: u64,
    /// Number of bytes to copy from the file.
    pub file_size: u64,
    /// Page permissions.
    pub perms: Perms,
}

impl Segment {
    /// First page-aligned address covered by the segment.
    #[must_use]
    pub const fn page_start(&self) -> u64 {
        self.vaddr & !(PAGE - 1)
    }

    /// One past the last page-aligned address covered (never overflows: validated).
    #[must_use]
    pub const fn page_end(&self) -> u64 {
        (self.vaddr + self.mem_size).next_multiple_of(PAGE)
    }
}

/// A validated `R_X86_64_RELATIVE` relocation: store `base + addend` (as a 64-bit
/// little endian value) at `base + offset`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Relocation {
    /// Target offset relative to the load base.
    pub offset: u64,
    /// Addend (two's complement).
    pub addend: u64,
}

/// A fully validated executable image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Image {
    /// Entry point (relative to the base for relocatable images).
    pub entry: u64,
    /// Loadable segments, sorted by address and non-overlapping at page granularity.
    pub segments: Vec<Segment>,
    /// Relocations to apply after copying the segments.
    pub relocations: Vec<Relocation>,
    /// `true` for position independent (`ET_DYN`) images.
    pub relocatable: bool,
    /// Page-aligned start of the image.
    pub span_start: u64,
    /// Page-aligned end of the image.
    pub span_end: u64,
}

/// Resource limits applied while parsing.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum number of `PT_LOAD` segments.
    pub max_segments: usize,
    /// Maximum number of relocations.
    pub max_relocations: usize,
    /// Maximum span of the image in bytes.
    pub max_span: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_segments: 16,
            max_relocations: 1 << 16,
            max_span: 64 << 20,
        }
    }
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn bytes<const N: usize>(&self, off: u64) -> Result<[u8; N], ElfError> {
        let start = usize::try_from(off).map_err(|_| ElfError::Truncated)?;
        let end = start.checked_add(N).ok_or(ElfError::Truncated)?;
        let slice = self.0.get(start..end).ok_or(ElfError::Truncated)?;
        let mut out = [0u8; N];
        out.copy_from_slice(slice);
        Ok(out)
    }
    fn u16(&self, off: u64) -> Result<u16, ElfError> {
        self.bytes::<2>(off).map(u16::from_le_bytes)
    }
    fn u32(&self, off: u64) -> Result<u32, ElfError> {
        self.bytes::<4>(off).map(u32::from_le_bytes)
    }
    fn u64(&self, off: u64) -> Result<u64, ElfError> {
        self.bytes::<8>(off).map(u64::from_le_bytes)
    }
}

struct Phdr {
    kind: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
}

fn read_phdr(r: &Reader<'_>, base: u64) -> Result<Phdr, ElfError> {
    Ok(Phdr {
        kind: r.u32(base)?,
        flags: r.u32(base + 4)?,
        offset: r.u64(base + 8)?,
        vaddr: r.u64(base + 16)?,
        filesz: r.u64(base + 32)?,
        memsz: r.u64(base + 40)?,
        align: r.u64(base + 48)?,
    })
}

fn file_range_ok(offset: u64, size: u64, file_len: usize) -> bool {
    matches!(offset.checked_add(size), Some(end) if end <= file_len as u64)
}

/// Validates an ELF image. See the module documentation for the enforced policy.
pub fn parse(file: &[u8], limits: &Limits) -> Result<Image, ElfError> {
    let r = Reader(file);
    if file.len() < EHDR_SIZE {
        return Err(ElfError::Truncated);
    }
    if file[..4] != *b"\x7fELF" {
        return Err(ElfError::BadMagic);
    }
    // ELFCLASS64, ELFDATA2LSB, EV_CURRENT
    if file[4] != 2 || file[5] != 1 || file[6] != 1 {
        return Err(ElfError::UnsupportedFormat);
    }
    let e_type = r.u16(16)?;
    let relocatable = match e_type {
        2 => false,
        3 => true,
        _ => return Err(ElfError::WrongType),
    };
    if r.u16(18)? != 62 {
        return Err(ElfError::WrongMachine);
    }
    if r.u32(20)? != 1 {
        return Err(ElfError::UnsupportedFormat);
    }
    let entry = r.u64(24)?;
    let phoff = r.u64(32)?;
    let ehsize = r.u16(52)?;
    let phentsize = r.u16(54)?;
    let phnum = r.u16(56)?;
    if usize::from(ehsize) != EHDR_SIZE || usize::from(phentsize) != PHDR_SIZE {
        return Err(ElfError::BadHeader);
    }
    if phnum == 0 || usize::from(phnum) > limits.max_segments.saturating_mul(4).max(8) {
        return Err(ElfError::TooManySegments);
    }
    let ph_bytes = u64::from(phnum) * PHDR_SIZE as u64;
    if !file_range_ok(phoff, ph_bytes, file.len()) {
        return Err(ElfError::Truncated);
    }

    let mut segments: Vec<Segment> = Vec::new();
    let mut dynamic: Option<(u64, u64)> = None;
    for i in 0..u64::from(phnum) {
        let ph = read_phdr(&r, phoff + i * PHDR_SIZE as u64)?;
        match ph.kind {
            PT_LOAD => {
                if ph.memsz == 0 {
                    continue;
                }
                if segments.len() >= limits.max_segments {
                    return Err(ElfError::TooManySegments);
                }
                if ph.filesz > ph.memsz || ph.vaddr.checked_add(ph.memsz).is_none() {
                    return Err(ElfError::BadSegment);
                }
                // `page_end` rounds up; make sure that cannot overflow either.
                if (ph.vaddr + ph.memsz)
                    .checked_next_multiple_of(PAGE)
                    .is_none()
                {
                    return Err(ElfError::BadSegment);
                }
                if !file_range_ok(ph.offset, ph.filesz, file.len()) {
                    return Err(ElfError::SegmentOutOfFile);
                }
                if ph.align > 1 {
                    if !ph.align.is_power_of_two() {
                        return Err(ElfError::Misaligned);
                    }
                    if ph.vaddr % ph.align != ph.offset % ph.align {
                        return Err(ElfError::Misaligned);
                    }
                }
                let perms = Perms {
                    read: ph.flags & PF_R != 0,
                    write: ph.flags & PF_W != 0,
                    exec: ph.flags & PF_X != 0,
                };
                if perms.write && perms.exec {
                    return Err(ElfError::WriteExecSegment);
                }
                segments.push(Segment {
                    vaddr: ph.vaddr,
                    mem_size: ph.memsz,
                    file_offset: ph.offset,
                    file_size: ph.filesz,
                    perms,
                });
            }
            PT_DYNAMIC => {
                if dynamic.is_some() || !file_range_ok(ph.offset, ph.filesz, file.len()) {
                    return Err(ElfError::BadDynamic);
                }
                dynamic = Some((ph.offset, ph.filesz));
            }
            PT_GNU_STACK => {
                if ph.flags & PF_X != 0 {
                    return Err(ElfError::ExecutableStack);
                }
            }
            PT_INTERP => return Err(ElfError::Interpreter),
            PT_TLS => return Err(ElfError::Tls),
            PT_NULL | PT_NOTE | PT_PHDR | PT_GNU_RELRO | PT_GNU_EH_FRAME | PT_GNU_PROPERTY => {}
            _ => return Err(ElfError::UnknownSegment),
        }
    }

    if segments.is_empty() {
        return Err(ElfError::NoLoadableSegments);
    }
    segments.sort_by_key(|s| s.vaddr);
    for pair in segments.windows(2) {
        if pair[0].page_end() > pair[1].page_start() {
            return Err(ElfError::OverlappingSegments);
        }
    }
    let span_start = segments[0].page_start();
    let span_end = segments
        .iter()
        .map(Segment::page_end)
        .max()
        .unwrap_or(span_start);
    if span_end - span_start > limits.max_span {
        return Err(ElfError::ImageTooLarge);
    }

    let entry_ok = segments
        .iter()
        .any(|s| s.perms.exec && entry >= s.vaddr && entry - s.vaddr < s.file_size);
    if !entry_ok {
        return Err(ElfError::EntryNotExecutable);
    }

    let relocations = match dynamic {
        Some((off, size)) => parse_dynamic(&r, off, size, &segments, relocatable, limits)?,
        None => Vec::new(),
    };

    Ok(Image {
        entry,
        segments,
        relocations,
        relocatable,
        span_start,
        span_end,
    })
}

/// Translates a virtual address range to a file offset (data must be file-backed).
fn vaddr_to_offset(segments: &[Segment], vaddr: u64, size: u64) -> Option<u64> {
    let end = vaddr.checked_add(size)?;
    segments.iter().find_map(|s| {
        (vaddr >= s.vaddr && end <= s.vaddr + s.file_size)
            .then(|| s.file_offset + (vaddr - s.vaddr))
    })
}

fn parse_dynamic(
    r: &Reader<'_>,
    off: u64,
    size: u64,
    segments: &[Segment],
    relocatable: bool,
    limits: &Limits,
) -> Result<Vec<Relocation>, ElfError> {
    let mut rela: Option<u64> = None;
    let mut rela_size = 0u64;
    let mut rela_ent = RELA_SIZE as u64;
    let entries = (size / DYN_SIZE as u64).min(MAX_DYN_ENTRIES as u64);
    let mut terminated = false;
    for i in 0..entries {
        let tag = r.u64(off + i * DYN_SIZE as u64)?;
        let val = r.u64(off + i * DYN_SIZE as u64 + 8)?;
        match tag {
            DT_NULL => {
                terminated = true;
                break;
            }
            DT_NEEDED => return Err(ElfError::DynamicLinking),
            DT_TEXTREL => return Err(ElfError::TextRelocations),
            DT_FLAGS if val & DF_TEXTREL != 0 => return Err(ElfError::TextRelocations),
            DT_PLTRELSZ | DT_RELSZ | DT_RELRSZ if val != 0 => {
                return Err(ElfError::UnsupportedRelocation);
            }
            DT_RELA => rela = Some(val),
            DT_RELASZ => rela_size = val,
            DT_RELAENT => rela_ent = val,
            _ => {}
        }
    }
    if !terminated {
        return Err(ElfError::BadDynamic);
    }
    let Some(rela) = rela else {
        return if rela_size == 0 {
            Ok(Vec::new())
        } else {
            Err(ElfError::BadDynamic)
        };
    };
    if rela_ent != RELA_SIZE as u64 || !rela_size.is_multiple_of(RELA_SIZE as u64) {
        return Err(ElfError::BadDynamic);
    }
    let count = rela_size / RELA_SIZE as u64;
    if count > limits.max_relocations as u64 {
        return Err(ElfError::TooManyRelocations);
    }
    if count > 0 && !relocatable {
        return Err(ElfError::UnsupportedRelocation);
    }
    let table = vaddr_to_offset(segments, rela, rela_size).ok_or(ElfError::BadDynamic)?;
    let mut out = Vec::new();
    for i in 0..count {
        let base = table + i * RELA_SIZE as u64;
        let r_offset = r.u64(base)?;
        let r_info = r.u64(base + 8)?;
        let r_addend = r.u64(base + 16)?;
        let kind = r_info as u32;
        let sym = r_info >> 32;
        match kind {
            R_X86_64_NONE => continue,
            R_X86_64_RELATIVE if sym == 0 => {}
            _ => return Err(ElfError::UnsupportedRelocation),
        }
        let inside = segments.iter().any(|s| {
            r_offset >= s.vaddr
                && r_offset
                    .checked_add(8)
                    .is_some_and(|end| end <= s.vaddr + s.mem_size)
        });
        if !inside {
            return Err(ElfError::RelocationOutOfBounds);
        }
        out.push(Relocation {
            offset: r_offset,
            addend: r_addend,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::XorShift;
    use std::vec;
    use std::vec::Vec;

    struct Ph {
        kind: u32,
        flags: u32,
        offset: u64,
        vaddr: u64,
        filesz: u64,
        memsz: u64,
        align: u64,
    }

    fn load(flags: u32, offset: u64, vaddr: u64, filesz: u64, memsz: u64) -> Ph {
        Ph {
            kind: PT_LOAD,
            flags,
            offset,
            vaddr,
            filesz,
            memsz,
            align: PAGE,
        }
    }

    /// Builds an ELF file with the given program headers, padded to `len` bytes.
    fn build(e_type: u16, entry: u64, phdrs: &[Ph], len: usize) -> Vec<u8> {
        let mut f = vec![0u8; len.max(EHDR_SIZE + phdrs.len() * PHDR_SIZE)];
        f[..4].copy_from_slice(b"\x7fELF");
        f[4] = 2;
        f[5] = 1;
        f[6] = 1;
        f[16..18].copy_from_slice(&e_type.to_le_bytes());
        f[18..20].copy_from_slice(&62u16.to_le_bytes());
        f[20..24].copy_from_slice(&1u32.to_le_bytes());
        f[24..32].copy_from_slice(&entry.to_le_bytes());
        f[32..40].copy_from_slice(&64u64.to_le_bytes());
        f[52..54].copy_from_slice(&64u16.to_le_bytes());
        f[54..56].copy_from_slice(&56u16.to_le_bytes());
        f[56..58].copy_from_slice(&(phdrs.len() as u16).to_le_bytes());
        for (i, p) in phdrs.iter().enumerate() {
            let b = EHDR_SIZE + i * PHDR_SIZE;
            f[b..b + 4].copy_from_slice(&p.kind.to_le_bytes());
            f[b + 4..b + 8].copy_from_slice(&p.flags.to_le_bytes());
            f[b + 8..b + 16].copy_from_slice(&p.offset.to_le_bytes());
            f[b + 16..b + 24].copy_from_slice(&p.vaddr.to_le_bytes());
            f[b + 24..b + 32].copy_from_slice(&p.vaddr.to_le_bytes());
            f[b + 32..b + 40].copy_from_slice(&p.filesz.to_le_bytes());
            f[b + 40..b + 48].copy_from_slice(&p.memsz.to_le_bytes());
            f[b + 48..b + 56].copy_from_slice(&p.align.to_le_bytes());
        }
        f
    }

    fn valid() -> Vec<u8> {
        build(
            3,
            0x1010,
            &[
                load(PF_R | PF_X, 0x1000, 0x1000, 0x100, 0x100),
                load(PF_R, 0x2000, 0x2000, 0x80, 0x80),
                load(PF_R | PF_W, 0x3000, 0x3000, 0x40, 0x2000),
                Ph {
                    kind: PT_GNU_STACK,
                    flags: PF_R | PF_W,
                    offset: 0,
                    vaddr: 0,
                    filesz: 0,
                    memsz: 0,
                    align: 16,
                },
            ],
            0x3100,
        )
    }

    fn lim() -> Limits {
        Limits::default()
    }

    #[test]
    fn accepts_valid_image() {
        let img = parse(&valid(), &lim()).unwrap();
        assert!(img.relocatable);
        assert_eq!(img.segments.len(), 3);
        assert_eq!(img.span_start, 0x1000);
        assert_eq!(img.span_end, 0x5000);
        assert!(img.relocations.is_empty());
    }

    #[test]
    fn rejects_wx_segment() {
        let f = build(
            3,
            0x1000,
            &[load(PF_R | PF_W | PF_X, 0x1000, 0x1000, 16, 16)],
            0x1100,
        );
        assert_eq!(parse(&f, &lim()), Err(ElfError::WriteExecSegment));
    }

    #[test]
    fn rejects_page_sharing() {
        let f = build(
            3,
            0x1000,
            &[
                load(PF_R | PF_X, 0x1000, 0x1000, 0x10, 0x10),
                load(PF_R | PF_W, 0x1800, 0x1800, 8, 8),
            ],
            0x2000,
        );
        assert_eq!(parse(&f, &lim()), Err(ElfError::OverlappingSegments));
    }

    #[test]
    fn rejects_exec_stack_interp_tls() {
        for (kind, flags, err) in [
            (PT_GNU_STACK, PF_R | PF_W | PF_X, ElfError::ExecutableStack),
            (PT_INTERP, PF_R, ElfError::Interpreter),
            (PT_TLS, PF_R, ElfError::Tls),
            (0x1234_5678, PF_R, ElfError::UnknownSegment),
        ] {
            let f = build(
                3,
                0x1000,
                &[
                    load(PF_R | PF_X, 0x1000, 0x1000, 0x10, 0x10),
                    Ph {
                        kind,
                        flags,
                        offset: 0,
                        vaddr: 0,
                        filesz: 0,
                        memsz: 0,
                        align: 1,
                    },
                ],
                0x1100,
            );
            assert_eq!(parse(&f, &lim()), Err(err));
        }
    }

    #[test]
    fn rejects_bad_entry_and_bounds() {
        let f = build(
            3,
            0x2000,
            &[load(PF_R | PF_X, 0x1000, 0x1000, 0x10, 0x10)],
            0x1100,
        );
        assert_eq!(parse(&f, &lim()), Err(ElfError::EntryNotExecutable));
        let f = build(
            3,
            0x1000,
            &[load(PF_R | PF_X, 0x1000, 0x1000, 0x1000, 0x1000)],
            0x1100,
        );
        assert_eq!(parse(&f, &lim()), Err(ElfError::SegmentOutOfFile));
        let f = build(
            3,
            0x1000,
            &[load(PF_R | PF_X, 0x1000, 0x1000, 0x20, 0x10)],
            0x1100,
        );
        assert_eq!(parse(&f, &lim()), Err(ElfError::BadSegment));
        let f = build(
            3,
            0x1000,
            &[load(PF_R | PF_X, 0x1000, u64::MAX - 4, 0x10, 0x10)],
            0x1100,
        );
        assert_eq!(parse(&f, &lim()), Err(ElfError::BadSegment));
        let f = build(
            3,
            0x1000,
            &[load(PF_R | PF_X, 0x1000, 0x1234, 0x10, 0x10)],
            0x1100,
        );
        assert_eq!(parse(&f, &lim()), Err(ElfError::Misaligned));
    }

    #[test]
    fn rejects_header_garbage() {
        assert_eq!(parse(b"", &lim()), Err(ElfError::Truncated));
        let mut f = valid();
        f[0] = 0;
        assert_eq!(parse(&f, &lim()), Err(ElfError::BadMagic));
        let mut f = valid();
        f[4] = 1;
        assert_eq!(parse(&f, &lim()), Err(ElfError::UnsupportedFormat));
        let mut f = valid();
        f[18] = 3;
        assert_eq!(parse(&f, &lim()), Err(ElfError::WrongMachine));
        let mut f = valid();
        f[16] = 4;
        assert_eq!(parse(&f, &lim()), Err(ElfError::WrongType));
        let mut f = valid();
        f[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(parse(&f, &lim()), Err(ElfError::Truncated));
    }

    /// Image with a PT_DYNAMIC inside the RW segment at file offset 0x3000.
    fn with_relocs(rela_entries: &[(u64, u64, u64)], extra_dyn: &[(u64, u64)]) -> Vec<u8> {
        let mut f = build(
            3,
            0x1000,
            &[
                load(PF_R | PF_X, 0x1000, 0x1000, 0x10, 0x10),
                load(PF_R, 0x2000, 0x2000, 0x400, 0x400),
                load(PF_R | PF_W, 0x3000, 0x3000, 0x200, 0x200),
                Ph {
                    kind: PT_DYNAMIC,
                    flags: PF_R | PF_W,
                    offset: 0x3000,
                    vaddr: 0x3000,
                    filesz: 0x100,
                    memsz: 0x100,
                    align: 8,
                },
            ],
            0x3200,
        );
        // RELA table at vaddr/offset 0x2000.
        for (i, (off, info, addend)) in rela_entries.iter().enumerate() {
            let b = 0x2000 + i * RELA_SIZE;
            f[b..b + 8].copy_from_slice(&off.to_le_bytes());
            f[b + 8..b + 16].copy_from_slice(&info.to_le_bytes());
            f[b + 16..b + 24].copy_from_slice(&addend.to_le_bytes());
        }
        let mut dyns = vec![
            (DT_RELA, 0x2000),
            (DT_RELASZ, (rela_entries.len() * RELA_SIZE) as u64),
            (DT_RELAENT, RELA_SIZE as u64),
        ];
        dyns.extend_from_slice(extra_dyn);
        dyns.push((DT_NULL, 0));
        for (i, (tag, val)) in dyns.iter().enumerate() {
            let b = 0x3000 + i * DYN_SIZE;
            f[b..b + 8].copy_from_slice(&tag.to_le_bytes());
            f[b + 8..b + 16].copy_from_slice(&val.to_le_bytes());
        }
        f
    }

    #[test]
    fn relocations() {
        let f = with_relocs(&[(0x3100, 8, 0x1000), (0x3108, 0, 0)], &[]);
        let img = parse(&f, &lim()).unwrap();
        assert_eq!(
            img.relocations,
            vec![Relocation {
                offset: 0x3100,
                addend: 0x1000
            }]
        );

        let f = with_relocs(&[(0x3100, 1, 0)], &[]);
        assert_eq!(parse(&f, &lim()), Err(ElfError::UnsupportedRelocation));
        let f = with_relocs(&[(0x3100, (5 << 32) | 8, 0)], &[]);
        assert_eq!(parse(&f, &lim()), Err(ElfError::UnsupportedRelocation));
        let f = with_relocs(&[(0x31fc, 8, 0)], &[]);
        assert_eq!(parse(&f, &lim()), Err(ElfError::RelocationOutOfBounds));
        let f = with_relocs(&[(0x9000, 8, 0)], &[]);
        assert_eq!(parse(&f, &lim()), Err(ElfError::RelocationOutOfBounds));
        let f = with_relocs(&[], &[(DT_TEXTREL, 0)]);
        assert_eq!(parse(&f, &lim()), Err(ElfError::TextRelocations));
        let f = with_relocs(&[], &[(DT_NEEDED, 1)]);
        assert_eq!(parse(&f, &lim()), Err(ElfError::DynamicLinking));
        let f = with_relocs(&[], &[(DT_FLAGS, DF_TEXTREL)]);
        assert_eq!(parse(&f, &lim()), Err(ElfError::TextRelocations));
    }

    #[test]
    fn truncation_never_panics() {
        let f = with_relocs(&[(0x3100, 8, 0x1000)], &[]);
        for len in 0..f.len() {
            let _ = parse(&f[..len], &lim());
        }
    }

    #[test]
    fn random_mutations_never_panic() {
        let mut rng = XorShift::new(0xe1f0_e1f0_1234_5678);
        let seeds = [valid(), with_relocs(&[(0x3100, 8, 0x1000)], &[])];
        for i in 0..20_000 {
            let mut f = seeds[i % 2].clone();
            for _ in 0..1 + rng.below(8) {
                let pos = rng.below(f.len().min(0x400) as u64) as usize;
                f[pos] = rng.next() as u8;
            }
            if let Ok(img) = parse(&f, &lim()) {
                for s in &img.segments {
                    assert!(
                        !(s.perms.write && s.perms.exec),
                        "W^X must hold for every accepted image"
                    );
                    assert!(s.file_offset + s.file_size <= f.len() as u64);
                }
            }
        }
        let mut junk = XorShift::new(9);
        for _ in 0..2000 {
            let len = junk.below(512) as usize;
            let _ = parse(&junk.bytes(len), &lim());
        }
    }

    /// Builds a random image that satisfies every rule of the loader.
    fn random_valid_image(rng: &mut XorShift) -> (Vec<u8>, usize) {
        let count = 1 + rng.below(5) as usize;
        let exec = rng.below(count as u64) as usize;
        let mut phdrs = Vec::new();
        let mut page = 1 + rng.below(4);
        let mut entry = 0;
        for i in 0..count {
            let pages = 1 + rng.below(3);
            let mem = pages * PAGE - rng.below(PAGE - 16);
            let file = if i == exec {
                16 + rng.below(mem - 15)
            } else {
                rng.below(mem + 1)
            };
            let flags = match (i == exec, rng.below(3)) {
                (true, _) => PF_R | PF_X,
                (false, 0) => PF_R,
                (false, 1) => PF_R | PF_W,
                (false, _) => PF_X,
            };
            let vaddr = page * PAGE;
            if i == exec {
                entry = vaddr + rng.below(file);
            }
            phdrs.push(load(flags, vaddr, vaddr, file, mem));
            page += pages + rng.below(3);
        }
        let len = (page * PAGE) as usize;
        (build(3, entry, &phdrs, len), count)
    }

    #[test]
    fn random_valid_images_are_accepted() {
        let mut rng = XorShift::new(0xe1f_600d);
        for _ in 0..3000 {
            let (file, count) = random_valid_image(&mut rng);
            let image = parse(&file, &lim()).expect("a valid image was rejected");
            assert_eq!(image.segments.len(), count);
            assert!(image.relocatable);
            for pair in image.segments.windows(2) {
                assert!(pair[0].page_end() <= pair[1].page_start());
            }
        }
    }

    #[test]
    fn one_violation_is_enough_to_reject() {
        let mut rng = XorShift::new(0xbad_e1f);
        for round in 0..3000 {
            let (file, count) = random_valid_image(&mut rng);
            let victim = EHDR_SIZE + rng.below(count as u64) as usize * PHDR_SIZE;
            let mut bad = file.clone();
            let expected = match round % 5 {
                0 => {
                    // Writable and executable.
                    bad[victim + 4..victim + 8]
                        .copy_from_slice(&(PF_R | PF_W | PF_X).to_le_bytes());
                    ElfError::WriteExecSegment
                }
                1 => {
                    // File size larger than memory size.
                    bad[victim + 32..victim + 40].copy_from_slice(&(u64::MAX / 2).to_le_bytes());
                    ElfError::BadSegment
                }
                2 => {
                    // Address range wraps around.
                    bad[victim + 16..victim + 24].copy_from_slice(&(u64::MAX - 100).to_le_bytes());
                    ElfError::BadSegment
                }
                3 => {
                    // Entry point far outside the image.
                    bad[24..32].copy_from_slice(&0xdead_0000_0000u64.to_le_bytes());
                    ElfError::EntryNotExecutable
                }
                _ => {
                    // Not for this machine.
                    bad[18..20].copy_from_slice(&183u16.to_le_bytes());
                    ElfError::WrongMachine
                }
            };
            assert_eq!(parse(&bad, &lim()), Err(expected), "round {round}");
        }
    }

    /// Long-running variant: `cargo test -p kalkan-core --release -- --ignored`.
    #[test]
    #[ignore = "stress test, takes a while without --release"]
    fn random_mutations_never_panic_stress() {
        let mut rng = XorShift::new(0x57e55);
        for _ in 0..40_000 {
            let (seed_image, _) = random_valid_image(&mut rng);
            for _ in 0..50 {
                let mut f = seed_image.clone();
                for _ in 0..1 + rng.below(6) {
                    let pos = rng.below(f.len().min(0x200) as u64) as usize;
                    f[pos] = rng.next() as u8;
                }
                if let Ok(img) = parse(&f, &lim()) {
                    for s in &img.segments {
                        assert!(!(s.perms.write && s.perms.exec));
                        assert!(s.file_offset + s.file_size <= f.len() as u64);
                    }
                }
            }
        }
    }
}
