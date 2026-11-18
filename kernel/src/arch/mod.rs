//! Architecture support. Kalkan currently targets x86-64 only.
//!
//! This is one of the few modules allowed to contain `unsafe` code. Everything it
//! exports to the rest of the kernel is a *safe* interface.

pub mod x86_64;

pub use self::x86_64::*;
