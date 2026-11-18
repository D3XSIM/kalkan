//! Arbitrary sequences of capability operations must never panic, never let a
//! derived capability exceed its parent's rights, and always leave the database
//! structurally consistent.

#![no_main]

use kcore::cspace::{CapDb, CapObject, Capability};
use kcore::rights::Rights;
use libfuzzer_sys::fuzz_target;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Obj(u8);

impl CapObject for Obj {}

fuzz_target!(|data: &[u8]| {
    let mut db = CapDb::new(256, 8);
    let spaces: Vec<_> = (0..4).map(|_| db.create_space(16).unwrap()).collect();
    let root = Capability { object: Obj(0), rights: Rights::ALL, badge: 0 };
    db.insert_root(spaces[0], 1, root).unwrap();

    for op in data.chunks_exact(4) {
        let a = spaces[usize::from(op[1] & 3)];
        let b = spaces[usize::from((op[1] >> 2) & 3)];
        let sa = u64::from(op[2] & 31); // includes out-of-range slots
        let sb = u64::from(op[3] & 31);
        match op[0] & 3 {
            0 | 1 => {
                if let Some(rights) = Rights::from_bits(u64::from(op[1] >> 4)) {
                    let badge = if op[0] & 4 != 0 { u64::from(op[0]) } else { 0 };
                    let parent = db.get(a, sa).map(|c| c.rights);
                    if db.mint((a, sa), (b, sb), rights, badge).is_ok() {
                        let child = db.get(b, sb).unwrap().rights;
                        assert!(parent.unwrap().contains(child), "rights escalation");
                        if a != b {
                            assert!(parent.unwrap().contains(Rights::GRANT), "transfer without GRANT");
                        }
                    }
                }
            }
            2 => {
                let _ = db.delete(a, sa);
            }
            _ => {
                let _ = db.revoke(a, sa);
            }
        }
        db.check_invariants().unwrap();
    }
});
