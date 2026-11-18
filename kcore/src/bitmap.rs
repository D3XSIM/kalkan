//! Physical frame bitmap allocator.
//!
//! One bit per 4 KiB frame; a set bit means *in use*. All frames start out used and
//! are explicitly released from the firmware memory map, so memory the kernel was
//! not told about can never be handed out. Freeing a frame that is already free is
//! detected and reported instead of silently corrupting the allocator.

/// Errors from [`FrameBitmap::free`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitmapError {
    /// Frame number outside the managed range.
    OutOfRange,
    /// The frame was already free.
    DoubleFree,
}

/// Bitmap over `frames` frames backed by caller-provided storage.
#[derive(Debug)]
pub struct FrameBitmap<'a> {
    words: &'a mut [u64],
    frames: usize,
    free: usize,
    hint: usize,
}

impl<'a> FrameBitmap<'a> {
    /// Number of `u64` words needed to track `frames` frames.
    #[must_use]
    pub const fn words_needed(frames: usize) -> usize {
        frames.div_ceil(64)
    }

    /// Creates a bitmap with every frame marked as used.
    ///
    /// Returns `None` if `words` is too small for `frames`.
    pub fn new(words: &'a mut [u64], frames: usize) -> Option<Self> {
        if words.len() < Self::words_needed(frames) {
            return None;
        }
        words.fill(u64::MAX);
        Some(Self {
            words,
            frames,
            free: 0,
            hint: 0,
        })
    }

    /// Continues with the same bitmap contents reachable through a different
    /// slice (the kernel uses this when it moves its direct map of physical
    /// memory: same memory, new virtual address). `words` must alias the storage
    /// this bitmap was created with; the old slice is not touched again.
    pub fn with_storage<'b>(self, words: &'b mut [u64]) -> Option<FrameBitmap<'b>> {
        if words.len() < Self::words_needed(self.frames) {
            return None;
        }
        Some(FrameBitmap {
            words,
            frames: self.frames,
            free: self.free,
            hint: self.hint,
        })
    }

    /// Total number of frames managed.
    #[must_use]
    pub const fn frames(&self) -> usize {
        self.frames
    }

    /// Number of currently free frames.
    #[must_use]
    pub const fn free_frames(&self) -> usize {
        self.free
    }

    fn is_used(&self, frame: usize) -> bool {
        self.words[frame / 64] & (1 << (frame % 64)) != 0
    }

    /// `true` if `frame` is in range and currently allocated.
    #[must_use]
    pub fn is_allocated(&self, frame: usize) -> bool {
        frame < self.frames && self.is_used(frame)
    }

    /// Marks `[start, start + count)` as free (used while parsing the memory map).
    /// Frames outside the managed range are ignored.
    pub fn release_range(&mut self, start: usize, count: usize) {
        let end = start.saturating_add(count).min(self.frames);
        for frame in start..end {
            if self.is_used(frame) {
                self.words[frame / 64] &= !(1 << (frame % 64));
                self.free += 1;
            }
        }
    }

    /// Marks `[start, start + count)` as used (reserving memory).
    pub fn reserve_range(&mut self, start: usize, count: usize) {
        let end = start.saturating_add(count).min(self.frames);
        for frame in start..end {
            if !self.is_used(frame) {
                self.words[frame / 64] |= 1 << (frame % 64);
                self.free -= 1;
            }
        }
    }

    /// Allocates one frame and returns its frame number.
    pub fn alloc(&mut self) -> Option<usize> {
        if self.free == 0 {
            return None;
        }
        let nwords = Self::words_needed(self.frames);
        for step in 0..nwords {
            let w = (self.hint + step) % nwords;
            let word = self.words[w];
            if word != u64::MAX {
                let bit = (!word).trailing_zeros() as usize;
                let frame = w * 64 + bit;
                if frame >= self.frames {
                    continue;
                }
                self.words[w] |= 1 << bit;
                self.free -= 1;
                self.hint = w;
                return Some(frame);
            }
        }
        None
    }

    /// Frees a frame previously returned by [`FrameBitmap::alloc`].
    pub fn free(&mut self, frame: usize) -> Result<(), BitmapError> {
        if frame >= self.frames {
            return Err(BitmapError::OutOfRange);
        }
        if !self.is_used(frame) {
            return Err(BitmapError::DoubleFree);
        }
        self.words[frame / 64] &= !(1 << (frame % 64));
        self.free += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::vec;

    #[test]
    fn starts_fully_used() {
        let mut words = vec![0u64; 4];
        let mut bm = FrameBitmap::new(&mut words, 200).unwrap();
        assert_eq!(bm.free_frames(), 0);
        assert_eq!(bm.alloc(), None);
    }

    #[test]
    fn alloc_free_and_double_free() {
        let mut words = vec![0u64; 4];
        let mut bm = FrameBitmap::new(&mut words, 200).unwrap();
        bm.release_range(10, 100);
        assert_eq!(bm.free_frames(), 100);
        let mut seen = HashSet::new();
        while let Some(f) = bm.alloc() {
            assert!((10..110).contains(&f), "frame {f} was never released");
            assert!(seen.insert(f), "frame {f} handed out twice");
        }
        assert_eq!(seen.len(), 100);
        let f = *seen.iter().next().unwrap();
        bm.free(f).unwrap();
        assert_eq!(bm.free(f), Err(BitmapError::DoubleFree));
        assert_eq!(bm.free(5000), Err(BitmapError::OutOfRange));
        assert_eq!(bm.alloc(), Some(f));
    }

    #[test]
    fn tail_bits_never_allocated() {
        let mut words = vec![0u64; 2];
        let mut bm = FrameBitmap::new(&mut words, 70).unwrap();
        bm.release_range(0, 1000);
        assert_eq!(bm.free_frames(), 70);
        for _ in 0..70 {
            assert!(bm.alloc().unwrap() < 70);
        }
        assert_eq!(bm.alloc(), None);
    }

    #[test]
    fn reserve_after_release() {
        let mut words = vec![0u64; 1];
        let mut bm = FrameBitmap::new(&mut words, 64).unwrap();
        bm.release_range(0, 64);
        bm.reserve_range(0, 32);
        assert_eq!(bm.free_frames(), 32);
        assert!(bm.alloc().unwrap() >= 32);
    }

    #[test]
    fn storage_can_be_swapped() {
        let mut words = vec![0u64; 2];
        let mut bm = FrameBitmap::new(&mut words, 100).unwrap();
        bm.release_range(0, 100);
        let a = bm.alloc().unwrap();
        let free = bm.free_frames();
        // Simulate "same memory, different address" with a copy of the contents.
        let mut copy = bm.words.to_vec();
        let mut too_small = vec![0u64; 1];
        let bm = bm.with_storage(&mut copy).unwrap();
        assert_eq!(bm.free_frames(), free);
        assert!(bm.is_allocated(a));
        assert!(bm.with_storage(&mut too_small).is_none());
    }

    #[test]
    fn storage_too_small() {
        let mut words = vec![0u64; 1];
        assert!(FrameBitmap::new(&mut words, 65).is_none());
    }

    /// Differential test against a `HashSet` of free frames.
    #[test]
    fn random_operations_match_a_model() {
        let mut rng = crate::testutil::XorShift::new(0xb17_3a9);
        const FRAMES: usize = 333;
        let mut words = vec![0u64; FrameBitmap::words_needed(FRAMES)];
        let mut bm = FrameBitmap::new(&mut words, FRAMES).unwrap();
        let mut free: HashSet<usize> = HashSet::new();
        for _ in 0..200_000 {
            let frame = rng.below(FRAMES as u64 + 40) as usize; // sometimes out of range
            let count = rng.below(9) as usize;
            match rng.below(6) {
                0 => {
                    bm.release_range(frame, count);
                    free.extend((frame..frame + count).filter(|f| *f < FRAMES));
                }
                1 => {
                    bm.reserve_range(frame, count);
                    for f in frame..frame + count {
                        free.remove(&f);
                    }
                }
                2 | 3 => match bm.alloc() {
                    Some(f) => assert!(free.remove(&f), "allocated frame {f} was not free"),
                    None => assert!(free.is_empty()),
                },
                _ => {
                    let expected = if frame >= FRAMES {
                        Err(BitmapError::OutOfRange)
                    } else if free.contains(&frame) {
                        Err(BitmapError::DoubleFree)
                    } else {
                        Ok(())
                    };
                    assert_eq!(bm.free(frame), expected);
                    if expected.is_ok() {
                        free.insert(frame);
                    }
                }
            }
            assert_eq!(bm.free_frames(), free.len());
        }
    }
}
