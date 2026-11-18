//! # kalkan-core
//!
//! The policy core of the Kalkan microkernel.
//!
//! Everything in this crate is **pure, 100% safe Rust** (`#![forbid(unsafe_code)]`)
//! and has no dependencies. It is compiled into the kernel *and* tested natively on
//! the host, which means the security-critical decision logic of the kernel —
//! who may access what, whether an executable is well-formed, how randomness is
//! generated — can be unit tested, property tested and fuzzed like any ordinary
//! library.
//!
//! | Module      | Responsibility                                                    |
//! |-------------|-------------------------------------------------------------------|
//! | [`abi`]     | System call numbers, error codes and the initial CSpace layout    |
//! | [`rights`]  | Capability access rights (monotonic: can only ever be reduced)   |
//! | [`cspace`]  | Global capability database with derivation tree and revocation    |
//! | [`arena`]   | Generational arena (ABA-safe object handles)                      |
//! | [`elf`]     | Strict, panic-free ELF64 validator and relocation parser          |
//! | [`bitmap`]  | Physical frame bitmap with double-free detection                  |
//! | [`chacha20`]| ChaCha20 block function and fast-key-erasure CSPRNG               |
//! | [`blake2b`] | BLAKE2b-512 (RFC 7693) used for boot-module integrity checks      |
//! | [`nospec`]  | Spectre-v1 hardened index clamping                                |

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod abi;
#[cfg(feature = "alloc")]
pub mod arena;
pub mod bitmap;
pub mod blake2b;
pub mod chacha20;
#[cfg(feature = "alloc")]
pub mod cspace;
#[cfg(feature = "alloc")]
pub mod elf;
pub mod hex;
pub mod nospec;
pub mod rights;

#[cfg(test)]
mod testutil;
