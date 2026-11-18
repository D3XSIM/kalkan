//! Generational arena.
//!
//! Kernel objects reference each other by [`Id`]s instead of pointers. Every slot
//! carries a generation counter that is bumped when the slot is freed, so a stale
//! id (for example one stored in a capability to an object that has since been
//! destroyed) can never accidentally resolve to a *new* object that reused the
//! slot — the classic ABA / use-after-free confusion.

use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

/// Typed handle to an element of an [`Arena<T>`].
pub struct Id<T> {
    index: u32,
    generation: u32,
    _marker: PhantomData<fn() -> T>,
}

impl<T> Id<T> {
    /// Slot index (for diagnostics only).
    #[must_use]
    pub const fn index(self) -> u32 {
        self.index
    }

    /// Generation (for diagnostics only).
    #[must_use]
    pub const fn generation(self) -> u32 {
        self.generation
    }
}

impl<T> Clone for Id<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for Id<T> {}
impl<T> PartialEq for Id<T> {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index && self.generation == other.generation
    }
}
impl<T> Eq for Id<T> {}
impl<T> fmt::Debug for Id<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{}.{}", self.index, self.generation)
    }
}

struct Entry<T> {
    generation: u32,
    value: Option<T>,
}

/// A generational arena with an optional hard capacity limit.
pub struct Arena<T> {
    entries: Vec<Entry<T>>,
    free: Vec<u32>,
    len: usize,
    limit: usize,
}

impl<T> fmt::Debug for Arena<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Arena")
            .field("len", &self.len)
            .field("limit", &self.limit)
            .finish()
    }
}

/// The arena reached its configured capacity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArenaFull;

impl<T> Arena<T> {
    /// Creates an empty arena that holds at most `limit` live elements.
    #[must_use]
    pub const fn with_limit(limit: usize) -> Self {
        Self {
            entries: Vec::new(),
            free: Vec::new(),
            len: 0,
            limit,
        }
    }

    /// Number of live elements.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// `true` if the arena holds no live elements.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Inserts a value, returning its id.
    pub fn insert(&mut self, value: T) -> Result<Id<T>, ArenaFull> {
        if self.len >= self.limit {
            return Err(ArenaFull);
        }
        let index = if let Some(index) = self.free.pop() {
            let entry = &mut self.entries[index as usize];
            debug_assert!(entry.value.is_none());
            entry.value = Some(value);
            index
        } else {
            let index = u32::try_from(self.entries.len()).map_err(|_| ArenaFull)?;
            self.entries.push(Entry {
                generation: 0,
                value: Some(value),
            });
            index
        };
        self.len += 1;
        let generation = self.entries[index as usize].generation;
        Ok(Id {
            index,
            generation,
            _marker: PhantomData,
        })
    }

    fn entry(&self, id: Id<T>) -> Option<&Entry<T>> {
        let index = crate::nospec::clamp(u64::from(id.index), self.entries.len())?;
        let entry = &self.entries[index];
        (entry.generation == id.generation).then_some(entry)
    }

    /// Returns a reference to the element, or `None` if the id is stale.
    #[must_use]
    pub fn get(&self, id: Id<T>) -> Option<&T> {
        self.entry(id)?.value.as_ref()
    }

    /// Returns a mutable reference to the element, or `None` if the id is stale.
    pub fn get_mut(&mut self, id: Id<T>) -> Option<&mut T> {
        let index = crate::nospec::clamp(u64::from(id.index), self.entries.len())?;
        let entry = &mut self.entries[index];
        if entry.generation != id.generation {
            return None;
        }
        entry.value.as_mut()
    }

    /// `true` if `id` refers to a live element.
    #[must_use]
    pub fn contains(&self, id: Id<T>) -> bool {
        self.get(id).is_some()
    }

    /// Removes the element and invalidates every outstanding copy of `id`.
    pub fn remove(&mut self, id: Id<T>) -> Option<T> {
        let index = crate::nospec::clamp(u64::from(id.index), self.entries.len())?;
        let entry = &mut self.entries[index];
        if entry.generation != id.generation {
            return None;
        }
        let value = entry.value.take()?;
        entry.generation = entry.generation.wrapping_add(1);
        self.free.push(id.index);
        self.len -= 1;
        Some(value)
    }

    /// Iterates over live `(id, &value)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (Id<T>, &T)> {
        self.entries.iter().enumerate().filter_map(|(i, e)| {
            e.value.as_ref().map(|v| {
                (
                    Id {
                        index: i as u32,
                        generation: e.generation,
                        _marker: PhantomData,
                    },
                    v,
                )
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_ids_never_resolve() {
        let mut a = Arena::with_limit(8);
        let x = a.insert(1).unwrap();
        assert_eq!(a.remove(x), Some(1));
        let y = a.insert(2).unwrap();
        assert_eq!(x.index(), y.index(), "slot is reused");
        assert_eq!(
            a.get(x),
            None,
            "but the stale id must not see the new value"
        );
        assert_eq!(a.get(y), Some(&2));
        assert_eq!(a.remove(x), None);
        assert_eq!(a.len(), 1);
    }

    #[test]
    fn limit_enforced() {
        let mut a = Arena::with_limit(2);
        a.insert(()).unwrap();
        a.insert(()).unwrap();
        assert_eq!(a.insert(()), Err(ArenaFull));
    }

    /// Differential test against a trivial model: every id ever issued either
    /// resolves to exactly the value stored under it, or to nothing.
    #[test]
    fn random_operations_match_a_model() {
        let mut rng = crate::testutil::XorShift::new(0xa5e7_a1e7);
        let mut arena = Arena::with_limit(24);
        let mut issued: std::vec::Vec<(Id<u64>, u64, bool)> = std::vec::Vec::new();
        for step in 0..200_000u64 {
            match rng.below(3) {
                0 | 1 => {
                    let live = issued.iter().filter(|e| e.2).count();
                    match arena.insert(step) {
                        Ok(id) => {
                            assert!(live < 24, "limit exceeded");
                            assert!(
                                !issued.iter().any(|e| e.2 && e.0 == id),
                                "id reused while live"
                            );
                            issued.push((id, step, true));
                        }
                        Err(ArenaFull) => assert_eq!(live, 24),
                    }
                }
                _ if !issued.is_empty() => {
                    let pick = rng.below(issued.len() as u64) as usize;
                    let (id, value, live) = issued[pick];
                    assert_eq!(arena.remove(id), live.then_some(value));
                    issued[pick].2 = false;
                }
                _ => {}
            }
            if step % 64 == 0 {
                for &(id, value, live) in &issued {
                    assert_eq!(arena.get(id).copied(), live.then_some(value));
                }
                assert_eq!(arena.len(), issued.iter().filter(|e| e.2).count());
                assert_eq!(arena.iter().count(), arena.len());
            }
            if issued.len() > 4096 {
                issued.retain(|e| e.2); // forget most dead ids, keep the test fast
            }
        }
    }
}
