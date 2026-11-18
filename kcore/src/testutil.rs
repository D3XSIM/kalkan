//! Deterministic pseudo-random numbers for property tests (no dev-dependencies).

pub(crate) struct XorShift(u64);

impl XorShift {
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    pub(crate) fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    pub(crate) fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    pub(crate) fn bytes(&mut self, len: usize) -> std::vec::Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }
}
