#![cfg_attr(not(feature = "std"), no_std)]

extern crate core;

pub mod ed25519;
pub mod error;
pub mod hachages;
pub mod messages_structs;
pub mod securite;

// Std features
#[cfg(feature = "x509")]
pub mod x509;
#[cfg(feature = "x509")]
pub mod x509_store;
#[cfg(all(feature = "openssl", feature = "dryoc", feature = "x25519"))]
pub mod x25519;
#[cfg(all(feature = "chiffrage"))]
pub mod chiffrage_mgs4;
#[cfg(all(feature = "chiffrage"))]
pub mod chiffrage_cles;
#[cfg(all(feature = "chiffrage"))]
pub mod chiffrage;
#[cfg(all(feature = "alloc"))]
pub mod serde_dates;

#[macro_use]
mod macros;

#[cfg(test)]
mod samples;

// Re-exports
pub use ed25519_dalek;
pub use heapless;
pub use openssl;
