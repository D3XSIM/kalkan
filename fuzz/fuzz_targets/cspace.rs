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
    let mut spaces: Vec<_> = (0..4).map(|_| db.create_space(16).unwrap()).collect();
    let root = Capability { object: Obj(0), rights: Rights::ALL, badge: 0 };
    db.insert_root(spaces[0], 1, root).unwrap();

    for op in data.chunks_exact(4) {
        let (ia, ib) = (usize::from(op[1] & 3), usize::from((op[1] >> 2) & 3));
        let (a, b) = (spaces[ia], spaces[ib]);
        let sa = u64::from(op[2] & 31); // includes out-of-range slots
        let sb = u64::from(op[3] & 31);
        let rights = Rights::from_bits(u64::from(op[1] >> 4)).unwrap_or(Rights::NONE);
        match op[0] & 7 {
            0..=2 => {
                let badge = if op[0] & 8 != 0 { u64::from(op[0]) } else { 0 };
                let parent = db.get(a, sa).map(|c| c.rights);
                if db.mint((a, sa), (b, sb), rights, badge).is_ok() {
                    let child = db.get(b, sb).unwrap().rights;
                    assert!(parent.unwrap().contains(child), "rights escalation");
                    if a != b {
                        assert!(parent.unwrap().contains(Rights::GRANT), "transfer without GRANT");
                    }
                    assert_ne!(sb, 0, "the null slot was filled");
                }
            }
            3 => {
                let _ = db.delete(a, sa);
            }
            4 => {
                if db.revoke(a, sa).is_ok() {
                    assert!(db.get(a, sa).is_ok(), "revoke removed the capability itself");
                }
            }
            5 => {
                // An object created from an untyped capability (may carry more
                // rights than its parent, but is destroyed with it).
                let cap = Capability { object: Obj(op[3]), rights, badge: 0 };
                let _ = db.insert_child((a, sa), (b, sb), cap);
            }
            6 => {
                let cap = Capability { object: Obj(op[2]), rights, badge: 0 };
                let _ = db.insert_root(a, sa, cap);
            }
            _ => {
                // A process dies: its whole capability space disappears.
                if db.destroy_space(a).is_ok() {
                    assert!(db.get(a, sa).is_err(), "stale space id still resolves");
                    spaces[ia] = db.create_space(16).unwrap();
                }
            }
        }
        db.check_invariants().unwrap();
    }
});
