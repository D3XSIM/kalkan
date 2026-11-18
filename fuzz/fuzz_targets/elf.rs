//! The ELF validator must never panic, and every image it accepts must satisfy the
//! loader's security policy.

#![no_main]

use kcore::elf::{Limits, parse};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(image) = parse(data, &Limits::default()) {
        assert!(!image.segments.is_empty());
        for (i, s) in image.segments.iter().enumerate() {
            assert!(!(s.perms.write && s.perms.exec), "accepted a W+X segment");
            assert!(s.file_size <= s.mem_size);
            assert!(s.file_offset + s.file_size <= data.len() as u64);
            if let Some(next) = image.segments.get(i + 1) {
                assert!(s.page_end() <= next.page_start(), "accepted overlapping segments");
            }
        }
        for r in &image.relocations {
            assert!(image.segments.iter().any(|s| r.offset >= s.vaddr && r.offset + 8 <= s.vaddr + s.mem_size));
        }
    }
});
