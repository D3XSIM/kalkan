//! Synchronisation primitives.
//!
//! Kalkan runs on one CPU and executes kernel code with interrupts disabled, so a
//! lock is never actually contended. `SpinLock` still uses a real atomic flag and
//! disables interrupts while held: a re-entrant acquisition (which would indicate
//! a kernel bug) is detected and turned into a panic instead of a silent deadlock
//! or data race.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch;

/// Interrupt-safe spin lock.
pub struct SpinLock<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

// SAFETY: access to `data` is serialised by `locked`.
unsafe impl<T: Send> Sync for SpinLock<T> {}
// SAFETY: moving the lock moves the data.
unsafe impl<T: Send> Send for SpinLock<T> {}

impl<T> SpinLock<T> {
    /// Creates an unlocked lock.
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(value),
        }
    }

    /// Acquires the lock, disabling interrupts until the guard is dropped.
    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        let irq = arch::interrupts_enabled();
        arch::disable_interrupts();
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // Single CPU + interrupts disabled: nobody can ever release it.
            panic!("deadlock: re-entrant SpinLock acquisition");
        }
        SpinLockGuard { lock: self, irq }
    }
}

/// RAII guard for [`SpinLock`].
pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
    irq: bool,
}

impl<T> Deref for SpinLockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard proves exclusive access.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for SpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the guard proves exclusive access.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for SpinLockGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
        if self.irq {
            arch::enable_interrupts();
        }
    }
}
