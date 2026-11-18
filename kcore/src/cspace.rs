//! The capability database.
//!
//! Kalkan has **no ambient authority**: a thread can only ever name kernel objects
//! through capabilities stored in its own capability space (CSpace), addressed by
//! slot number. This module implements all capability spaces of the system in a
//! single database, together with the *derivation tree* that records which
//! capability was derived from which.
//!
//! ## Security invariants (tested below)
//!
//! 1. **Monotonicity** — a derived capability never has a right its parent lacks.
//! 2. **Confinement** — moving a capability to *another* CSpace requires the
//!    [`Rights::GRANT`] right on it.
//! 3. **Complete revocation** — after `revoke(c)`, no capability derived from `c`
//!    (directly or transitively, in any CSpace) survives.
//! 4. **No dangling references** — slots and nodes always agree; ids of deleted
//!    capabilities and destroyed CSpaces never resolve again (generational ids).
//! 5. **Bounded resources** — the total number of capabilities and CSpaces is
//!    capped, so user space cannot exhaust kernel memory through this database.
//! 6. **Slot 0 is the null slot** — it is always empty and can never be a
//!    destination, so a zeroed argument can never name a capability.
//!
//! Objects created from an untyped memory budget are recorded as *retyped*
//! children of the untyped capability: revoking the untyped capability destroys
//! everything that was created from it. Retyped children are the one case where a
//! child may carry rights its parent lacks (they refer to a different object).

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use crate::abi;
use crate::arena::{Arena, Id};
use crate::nospec;
use crate::rights::Rights;

/// Behaviour of the objects referenced by capabilities.
pub trait CapObject: Clone {
    /// Produces the object stored in a capability *derived* from one referring to
    /// `self`. The default is a plain clone; objects with per-capability state (for
    /// example a frame's current mapping) reset it here.
    #[must_use]
    fn derive(&self) -> Self {
        self.clone()
    }
}

/// A capability: an unforgeable reference to an object plus access rights.
#[derive(Clone, PartialEq, Eq)]
pub struct Capability<O> {
    /// The referenced object.
    pub object: O,
    /// Access rights.
    pub rights: Rights,
    /// Badge delivered to receivers of IPC through this capability (0 = none).
    pub badge: u64,
}

impl<O: fmt::Debug> fmt::Debug for Capability<O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Cap({:?}, {}, badge={:#x})",
            self.object, self.rights, self.badge
        )
    }
}

/// A node of the derivation tree.
pub struct Node<O> {
    cap: Capability<O>,
    parent: Option<CapId<O>>,
    children: Vec<CapId<O>>,
    space: SpaceId<O>,
    slot: usize,
    /// Created from an untyped parent (refers to a different object).
    retyped: bool,
}

/// A capability space: a fixed-size array of slots.
pub struct Space<O> {
    slots: Vec<Option<CapId<O>>>,
}

impl<O: fmt::Debug> fmt::Debug for Node<O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Node")
            .field("cap", &self.cap)
            .field("parent", &self.parent)
            .field("children", &self.children.len())
            .finish()
    }
}

impl<O> fmt::Debug for Space<O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Space")
            .field("slots", &self.slots.len())
            .finish()
    }
}

/// Identifies a capability in the database.
pub type CapId<O> = Id<Node<O>>;
/// Identifies a capability space.
pub type SpaceId<O> = Id<Space<O>>;

/// Errors returned by capability operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapError {
    /// Slot index out of range.
    BadSlot,
    /// Slot is empty.
    EmptySlot,
    /// Destination slot already holds a capability.
    SlotOccupied,
    /// Missing right (including attempted escalation or transfer without GRANT).
    PermissionDenied,
    /// Tried to re-badge an already badged capability.
    BadgeAlreadySet,
    /// The capability space no longer exists.
    StaleSpace,
    /// The global capability or space limit was reached.
    OutOfCapacity,
}

impl From<CapError> for abi::Error {
    fn from(e: CapError) -> Self {
        match e {
            CapError::BadSlot => Self::BadSlot,
            CapError::EmptySlot => Self::EmptySlot,
            CapError::SlotOccupied => Self::SlotOccupied,
            CapError::PermissionDenied => Self::PermissionDenied,
            CapError::BadgeAlreadySet => Self::InvalidArgument,
            CapError::StaleSpace => Self::Dead,
            CapError::OutOfCapacity => Self::OutOfMemory,
        }
    }
}

/// Address of a capability: (space, slot index).
pub type Slot<O> = (SpaceId<O>, u64);

/// The capability database.
pub struct CapDb<O> {
    nodes: Arena<Node<O>>,
    spaces: Arena<Space<O>>,
}

impl<O> fmt::Debug for CapDb<O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapDb")
            .field("capabilities", &self.nodes.len())
            .field("spaces", &self.spaces.len())
            .finish()
    }
}

impl<O: CapObject> CapDb<O> {
    /// Creates an empty database with hard limits.
    #[must_use]
    pub const fn new(max_caps: usize, max_spaces: usize) -> Self {
        Self {
            nodes: Arena::with_limit(max_caps),
            spaces: Arena::with_limit(max_spaces),
        }
    }

    /// Number of live capabilities.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.nodes.len()
    }

    /// `true` if there are no capabilities.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Creates a new, empty capability space with `slots` slots.
    pub fn create_space(&mut self, slots: usize) -> Result<SpaceId<O>, CapError> {
        if slots == 0 || slots > 4096 {
            return Err(CapError::BadSlot);
        }
        self.spaces
            .insert(Space {
                slots: vec![None; slots],
            })
            .map_err(|_| CapError::OutOfCapacity)
    }

    /// `true` if the space exists.
    #[must_use]
    pub fn space_exists(&self, space: SpaceId<O>) -> bool {
        self.spaces.contains(space)
    }

    /// Destroys a capability space, deleting every capability it holds.
    ///
    /// Children of deleted capabilities living in *other* spaces are re-parented
    /// (exactly like [`CapDb::delete`]), so a later revocation from an ancestor
    /// still reaches them.
    pub fn destroy_space(&mut self, space: SpaceId<O>) -> Result<Vec<Capability<O>>, CapError> {
        let slots = self
            .spaces
            .get(space)
            .ok_or(CapError::StaleSpace)?
            .slots
            .len();
        let mut removed = Vec::new();
        for slot in 0..slots {
            if let Ok(cap) = self.delete(space, slot as u64) {
                removed.push(cap);
            }
        }
        self.spaces.remove(space);
        Ok(removed)
    }

    fn resolve(&self, space: SpaceId<O>, slot: u64) -> Result<(usize, Option<CapId<O>>), CapError> {
        let sp = self.spaces.get(space).ok_or(CapError::StaleSpace)?;
        let index = nospec::clamp(slot, sp.slots.len()).ok_or(CapError::BadSlot)?;
        Ok((index, sp.slots[index]))
    }

    /// Validates a destination slot: in range, not the null slot, and empty.
    fn resolve_dst(&self, space: SpaceId<O>, slot: u64) -> Result<usize, CapError> {
        match self.resolve(space, slot)? {
            (0, _) => Err(CapError::BadSlot),
            (_, Some(_)) => Err(CapError::SlotOccupied),
            (index, None) => Ok(index),
        }
    }

    fn cap_id(&self, space: SpaceId<O>, slot: u64) -> Result<CapId<O>, CapError> {
        self.resolve(space, slot)?.1.ok_or(CapError::EmptySlot)
    }

    /// Returns the capability in a slot.
    pub fn get(&self, space: SpaceId<O>, slot: u64) -> Result<&Capability<O>, CapError> {
        let id = self.cap_id(space, slot)?;
        Ok(&self.nodes.get(id).ok_or(CapError::EmptySlot)?.cap)
    }

    /// Returns the capability in a slot if it carries at least the rights `need`.
    pub fn lookup(
        &self,
        space: SpaceId<O>,
        slot: u64,
        need: Rights,
    ) -> Result<&Capability<O>, CapError> {
        let cap = self.get(space, slot)?;
        if cap.rights.contains(need) {
            Ok(cap)
        } else {
            Err(CapError::PermissionDenied)
        }
    }

    /// Mutable access to the object of a capability (rights and badge are immutable).
    pub fn object_mut(&mut self, space: SpaceId<O>, slot: u64) -> Result<&mut O, CapError> {
        let id = self.cap_id(space, slot)?;
        Ok(&mut self
            .nodes
            .get_mut(id)
            .ok_or(CapError::EmptySlot)?
            .cap
            .object)
    }

    /// Returns `true` if a slot exists and is empty.
    pub fn is_free(&self, space: SpaceId<O>, slot: u64) -> Result<bool, CapError> {
        Ok(self.resolve(space, slot)?.1.is_none())
    }

    fn place(&mut self, node: Node<O>) -> Result<CapId<O>, CapError> {
        let (space, slot) = (node.space, node.slot);
        let id = self
            .nodes
            .insert(node)
            .map_err(|_| CapError::OutOfCapacity)?;
        match self.spaces.get_mut(space) {
            Some(sp) => sp.slots[slot] = Some(id),
            None => {
                self.nodes.remove(id);
                return Err(CapError::StaleSpace);
            }
        }
        Ok(id)
    }

    /// Inserts an *original* capability (one not derived from any other).
    ///
    /// Only the kernel creates original capabilities: at boot and when a new object
    /// is created by `untyped_retype`.
    pub fn insert_root(
        &mut self,
        space: SpaceId<O>,
        slot: u64,
        cap: Capability<O>,
    ) -> Result<CapId<O>, CapError> {
        let index = self.resolve_dst(space, slot)?;
        self.place(Node {
            cap,
            parent: None,
            children: Vec::new(),
            space,
            slot: index,
            retyped: false,
        })
    }

    /// Inserts a capability to a *new* object created from the untyped capability
    /// `parent`, recording it as a retyped child: revoking `parent` destroys it.
    pub fn insert_child(
        &mut self,
        parent: Slot<O>,
        dst: Slot<O>,
        cap: Capability<O>,
    ) -> Result<CapId<O>, CapError> {
        let parent_id = self.cap_id(parent.0, parent.1)?;
        let index = self.resolve_dst(dst.0, dst.1)?;
        let id = self.place(Node {
            cap,
            parent: Some(parent_id),
            children: Vec::new(),
            space: dst.0,
            slot: index,
            retyped: true,
        })?;
        if let Some(p) = self.nodes.get_mut(parent_id) {
            p.children.push(id);
        }
        Ok(id)
    }

    /// Derives a new capability from `src` into the empty slot `dst`.
    ///
    /// * `rights` must be a subset of the source's rights (no escalation).
    /// * `badge == 0` keeps the source's badge; a non-zero badge may only be set on
    ///   an unbadged source.
    /// * If `dst` is in a different capability space than `src`, the source must
    ///   carry [`Rights::GRANT`] (confinement).
    pub fn mint(
        &mut self,
        src: Slot<O>,
        dst: Slot<O>,
        rights: Rights,
        badge: u64,
    ) -> Result<CapId<O>, CapError> {
        let src_id = self.cap_id(src.0, src.1)?;
        let dst_index = self.resolve_dst(dst.0, dst.1)?;
        let parent = &self.nodes.get(src_id).ok_or(CapError::EmptySlot)?.cap;
        if src.0 != dst.0 && !parent.rights.contains(Rights::GRANT) {
            return Err(CapError::PermissionDenied);
        }
        let rights = parent
            .rights
            .derive(rights)
            .map_err(|_| CapError::PermissionDenied)?;
        let badge = match (badge, parent.badge) {
            (0, inherited) => inherited,
            (new, 0) => new,
            (_, _) => return Err(CapError::BadgeAlreadySet),
        };
        let cap = Capability {
            object: parent.object.derive(),
            rights,
            badge,
        };
        let id = self.place(Node {
            cap,
            parent: Some(src_id),
            children: Vec::new(),
            space: dst.0,
            slot: dst_index,
            retyped: false,
        })?;
        if let Some(p) = self.nodes.get_mut(src_id) {
            p.children.push(id);
        }
        Ok(id)
    }

    fn unlink(&mut self, id: CapId<O>) -> Option<Node<O>> {
        let node = self.nodes.remove(id)?;
        if let Some(sp) = self.spaces.get_mut(node.space)
            && sp.slots[node.slot] == Some(id)
        {
            sp.slots[node.slot] = None;
        }
        Some(node)
    }

    /// Deletes the capability in `slot`.
    ///
    /// Its children survive and are re-parented to its parent, so that revoking any
    /// ancestor still reaches them.
    pub fn delete(&mut self, space: SpaceId<O>, slot: u64) -> Result<Capability<O>, CapError> {
        let id = self.cap_id(space, slot)?;
        let node = self.unlink(id).ok_or(CapError::EmptySlot)?;
        if let Some(parent) = node.parent.and_then(|p| self.nodes.get_mut(p)) {
            parent.children.retain(|c| *c != id);
            parent.children.extend_from_slice(&node.children);
        }
        for child in &node.children {
            if let Some(c) = self.nodes.get_mut(*child) {
                c.parent = node.parent;
            }
        }
        Ok(node.cap)
    }

    /// Deletes every capability transitively derived from the one in `slot`, in
    /// every capability space. The capability itself is kept.
    pub fn revoke(&mut self, space: SpaceId<O>, slot: u64) -> Result<Vec<Capability<O>>, CapError> {
        let id = self.cap_id(space, slot)?;
        let mut stack = match self.nodes.get_mut(id) {
            Some(node) => core::mem::take(&mut node.children),
            None => return Err(CapError::EmptySlot),
        };
        let mut removed = Vec::new();
        while let Some(child) = stack.pop() {
            if let Some(node) = self.unlink(child) {
                stack.extend_from_slice(&node.children);
                removed.push(node.cap);
            }
        }
        Ok(removed)
    }

    /// Iterates over every capability (diagnostics and kernel bookkeeping).
    pub fn iter(&self) -> impl Iterator<Item = &Capability<O>> {
        self.nodes.iter().map(|(_, n)| &n.cap)
    }

    /// Verifies all structural and security invariants. Used by tests and by the
    /// kernel's boot-time self check.
    pub fn check_invariants(&self) -> Result<(), &'static str> {
        for (id, node) in self.nodes.iter() {
            let space = self
                .spaces
                .get(node.space)
                .ok_or("node in destroyed space")?;
            if space.slots.get(node.slot).copied().flatten() != Some(id) {
                return Err("slot/node mismatch");
            }
            if let Some(pid) = node.parent {
                let parent = self.nodes.get(pid).ok_or("dangling parent")?;
                if !node.retyped && !parent.cap.rights.contains(node.cap.rights) {
                    return Err("child has more rights than parent");
                }
                if !parent.children.contains(&id) {
                    return Err("parent does not list child");
                }
            }
            for c in &node.children {
                let child = self.nodes.get(*c).ok_or("dangling child")?;
                if child.parent != Some(id) {
                    return Err("child does not point back to parent");
                }
            }
        }
        for (sid, space) in self.spaces.iter() {
            for (slot, entry) in space.slots.iter().enumerate() {
                if let Some(id) = entry {
                    let node = self.nodes.get(*id).ok_or("slot references dead cap")?;
                    if node.space != sid || node.slot != slot {
                        return Err("node location mismatch");
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::XorShift;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Obj(u32);
    impl CapObject for Obj {}

    fn cap(o: u32, r: Rights) -> Capability<Obj> {
        Capability {
            object: Obj(o),
            rights: r,
            badge: 0,
        }
    }

    #[test]
    fn mint_cannot_escalate() {
        let mut db = CapDb::new(64, 4);
        let s = db.create_space(8).unwrap();
        db.insert_root(s, 1, cap(1, Rights::READ)).unwrap();
        assert_eq!(
            db.mint((s, 1), (s, 2), Rights::ALL, 0),
            Err(CapError::PermissionDenied)
        );
        assert_eq!(
            db.mint((s, 1), (s, 2), Rights::READ.union(Rights::WRITE), 0),
            Err(CapError::PermissionDenied)
        );
        db.mint((s, 1), (s, 2), Rights::READ, 0).unwrap();
        db.mint((s, 2), (s, 3), Rights::NONE, 0).unwrap();
        assert_eq!(
            db.mint((s, 3), (s, 4), Rights::READ, 0),
            Err(CapError::PermissionDenied)
        );
        db.check_invariants().unwrap();
    }

    #[test]
    fn transfer_requires_grant() {
        let mut db = CapDb::new(64, 4);
        let a = db.create_space(8).unwrap();
        let b = db.create_space(8).unwrap();
        db.insert_root(a, 1, cap(1, Rights::READ.union(Rights::WRITE)))
            .unwrap();
        assert_eq!(
            db.mint((a, 1), (b, 1), Rights::READ, 0),
            Err(CapError::PermissionDenied)
        );
        db.insert_root(a, 2, cap(2, Rights::READ.union(Rights::GRANT)))
            .unwrap();
        db.mint((a, 2), (b, 1), Rights::READ, 0).unwrap();
        // The copy in `b` lacks GRANT, so `b` cannot pass it on to anyone else.
        let c = db.create_space(8).unwrap();
        assert_eq!(
            db.mint((b, 1), (c, 1), Rights::READ, 0),
            Err(CapError::PermissionDenied)
        );
        db.check_invariants().unwrap();
    }

    #[test]
    fn badges_are_write_once() {
        let mut db = CapDb::new(64, 4);
        let s = db.create_space(8).unwrap();
        db.insert_root(s, 1, cap(1, Rights::ALL)).unwrap();
        db.mint((s, 1), (s, 2), Rights::ALL, 0x42).unwrap();
        assert_eq!(db.get(s, 2).unwrap().badge, 0x42);
        assert_eq!(
            db.mint((s, 2), (s, 3), Rights::ALL, 0x43),
            Err(CapError::BadgeAlreadySet)
        );
        db.mint((s, 2), (s, 3), Rights::READ, 0).unwrap();
        assert_eq!(db.get(s, 3).unwrap().badge, 0x42, "badge is inherited");
    }

    #[test]
    fn revoke_is_complete_across_spaces() {
        let mut db = CapDb::new(64, 4);
        let a = db.create_space(8).unwrap();
        let b = db.create_space(8).unwrap();
        db.insert_root(a, 1, cap(7, Rights::ALL)).unwrap();
        db.mint((a, 1), (a, 2), Rights::ALL, 0).unwrap();
        db.mint((a, 2), (b, 1), Rights::ALL, 0).unwrap();
        db.mint((b, 1), (b, 2), Rights::READ, 0).unwrap();
        // Deleting an intermediate node must not let its subtree escape revocation.
        db.delete(a, 2).unwrap();
        let removed = db.revoke(a, 1).unwrap();
        assert_eq!(removed.len(), 2);
        assert_eq!(db.get(b, 1).err(), Some(CapError::EmptySlot));
        assert_eq!(db.get(b, 2).err(), Some(CapError::EmptySlot));
        assert!(db.get(a, 1).is_ok(), "revoke keeps the capability itself");
        assert_eq!(db.len(), 1);
        db.check_invariants().unwrap();
    }

    #[test]
    fn bounds_and_staleness() {
        let mut db: CapDb<Obj> = CapDb::new(4, 2);
        let s = db.create_space(4).unwrap();
        assert_eq!(db.get(s, 4).err(), Some(CapError::BadSlot));
        assert_eq!(db.get(s, u64::MAX).err(), Some(CapError::BadSlot));
        assert_eq!(db.get(s, 3).err(), Some(CapError::EmptySlot));
        db.insert_root(s, 1, cap(1, Rights::ALL)).unwrap();
        assert_eq!(
            db.insert_root(s, 1, cap(1, Rights::ALL)).err(),
            Some(CapError::SlotOccupied)
        );
        let removed = db.destroy_space(s).unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(db.get(s, 1).err(), Some(CapError::StaleSpace));
        let s2 = db.create_space(4).unwrap();
        assert_ne!(s, s2);
        assert_eq!(
            db.get(s, 1).err(),
            Some(CapError::StaleSpace),
            "stale id never resolves"
        );
    }

    #[test]
    fn capacity_limit() {
        let mut db = CapDb::new(3, 1);
        let s = db.create_space(8).unwrap();
        db.insert_root(s, 1, cap(1, Rights::ALL)).unwrap();
        db.mint((s, 1), (s, 2), Rights::ALL, 0).unwrap();
        db.mint((s, 1), (s, 3), Rights::ALL, 0).unwrap();
        assert_eq!(
            db.mint((s, 1), (s, 4), Rights::ALL, 0),
            Err(CapError::OutOfCapacity)
        );
        assert_eq!(db.create_space(1), Err(CapError::OutOfCapacity));
        db.check_invariants().unwrap();
    }

    #[test]
    fn null_slot_is_never_a_destination() {
        let mut db = CapDb::new(16, 2);
        let s = db.create_space(8).unwrap();
        assert_eq!(
            db.insert_root(s, 0, cap(1, Rights::ALL)).err(),
            Some(CapError::BadSlot)
        );
        db.insert_root(s, 1, cap(1, Rights::ALL)).unwrap();
        assert_eq!(
            db.mint((s, 1), (s, 0), Rights::ALL, 0).err(),
            Some(CapError::BadSlot)
        );
        assert_eq!(db.get(s, 0).err(), Some(CapError::EmptySlot));
    }

    #[test]
    fn revoking_an_untyped_destroys_retyped_objects() {
        let mut db = CapDb::new(16, 2);
        let a = db.create_space(8).unwrap();
        let b = db.create_space(8).unwrap();
        // An untyped budget with WRITE only can still create objects with full rights.
        db.insert_root(a, 1, cap(100, Rights::ALL)).unwrap();
        db.mint((a, 1), (a, 2), Rights::WRITE.union(Rights::GRANT), 0)
            .unwrap();
        db.insert_child((a, 2), (a, 3), cap(7, Rights::ALL))
            .unwrap();
        db.mint((a, 3), (b, 1), Rights::READ, 0).unwrap();
        db.check_invariants().unwrap();
        let removed = db.revoke(a, 2).unwrap();
        assert_eq!(removed.len(), 2, "the object and its derived copy");
        assert_eq!(db.get(a, 3).err(), Some(CapError::EmptySlot));
        assert_eq!(db.get(b, 1).err(), Some(CapError::EmptySlot));
        db.check_invariants().unwrap();
    }

    /// Randomised model check: run thousands of arbitrary operations and verify the
    /// invariants after each one, plus "rights only ever shrink along any path".
    #[test]
    fn randomized_operations_preserve_invariants() {
        let mut rng = XorShift::new(0x5eed_1234_abcd_ef01);
        for round in 0..40 {
            let mut db = CapDb::new(200, 8);
            let spaces: Vec<_> = (0..4).map(|_| db.create_space(16).unwrap()).collect();
            db.insert_root(spaces[0], 1, cap(round, Rights::ALL))
                .unwrap();
            for _ in 0..600 {
                let a = spaces[rng.below(4) as usize];
                let b = spaces[rng.below(4) as usize];
                let sa = rng.below(18); // includes out-of-range slots
                let sb = rng.below(18);
                match rng.below(10) {
                    0..=5 => {
                        let rights = Rights::from_bits(rng.below(16)).unwrap();
                        let badge = if rng.below(4) == 0 { rng.next() } else { 0 };
                        let before = db.get(a, sa).ok().map(|c| c.rights);
                        if db.mint((a, sa), (b, sb), rights, badge).is_ok() {
                            let parent_rights = before.expect("mint from empty slot succeeded");
                            assert!(parent_rights.contains(db.get(b, sb).unwrap().rights));
                        }
                    }
                    6 | 7 => {
                        let _ = db.delete(a, sa);
                    }
                    _ => {
                        if let Ok(()) = db.revoke(a, sa).map(|_| ()) {
                            assert!(db.get(a, sa).is_ok());
                        }
                    }
                }
                db.check_invariants().unwrap();
            }
        }
    }
}
