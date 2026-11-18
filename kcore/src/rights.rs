//! Capability access rights.
//!
//! Rights are **monotonic**: a capability derived from another one can only carry a
//! subset of its parent's rights. The only way to obtain a right is to be handed a
//! capability that already has it. There is no operation in the kernel that can
//! add a right to an existing capability.

use core::fmt;

/// A set of access rights carried by a capability.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Rights(u8);

impl Rights {
    /// No rights at all.
    pub const NONE: Self = Self(0);
    /// Read / receive / inspect.
    pub const READ: Self = Self(1 << 0);
    /// Write / send / modify.
    pub const WRITE: Self = Self(1 << 1);
    /// Execute (only meaningful for frames).
    pub const EXEC: Self = Self(1 << 2);
    /// May be transferred to another protection domain.
    pub const GRANT: Self = Self(1 << 3);
    /// Every right.
    pub const ALL: Self = Self(0b1111);

    /// Builds a rights set from raw bits, rejecting unknown bits.
    #[must_use]
    pub const fn from_bits(bits: u64) -> Option<Self> {
        if bits & !(Self::ALL.0 as u64) != 0 {
            None
        } else {
            Some(Self(bits as u8))
        }
    }

    /// Raw bit representation.
    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0 as u64
    }

    /// `true` if every right in `other` is also in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Set union.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Set intersection.
    #[must_use]
    pub const fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Returns the rights of a capability derived from `self` with the requested
    /// rights, or an error if that would *add* a right.
    pub const fn derive(self, requested: Self) -> Result<Self, RightsEscalation> {
        if self.contains(requested) {
            Ok(requested)
        } else {
            Err(RightsEscalation)
        }
    }
}

/// Attempt to derive a capability with more rights than its parent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RightsEscalation;

impl fmt::Debug for Rights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Rights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let flag = |r: Self, c: char| if self.contains(r) { c } else { '-' };
        write!(
            f,
            "{}{}{}{}",
            flag(Self::READ, 'r'),
            flag(Self::WRITE, 'w'),
            flag(Self::EXEC, 'x'),
            flag(Self::GRANT, 'g')
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_bits_rejected() {
        assert_eq!(Rights::from_bits(0b1_0000), None);
        assert_eq!(Rights::from_bits(u64::MAX), None);
        assert_eq!(
            Rights::from_bits(0b0101),
            Some(Rights::READ.union(Rights::EXEC))
        );
    }

    #[test]
    fn derive_never_escalates() {
        // Exhaustive: for every (parent, requested) pair, a successful derivation
        // must produce a subset of the parent.
        for p in 0..=0b1111u64 {
            for r in 0..=0b1111u64 {
                let parent = Rights::from_bits(p).unwrap();
                let req = Rights::from_bits(r).unwrap();
                match parent.derive(req) {
                    Ok(child) => {
                        assert!(parent.contains(child));
                        assert_eq!(child, req);
                    }
                    Err(RightsEscalation) => assert!(!parent.contains(req)),
                }
            }
        }
    }

    #[test]
    fn display() {
        extern crate std;
        use std::format;
        assert_eq!(format!("{}", Rights::ALL), "rwxg");
        assert_eq!(format!("{}", Rights::READ.union(Rights::GRANT)), "r--g");
    }
}
