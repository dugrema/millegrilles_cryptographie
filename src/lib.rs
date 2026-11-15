#![cfg_attr(not(feature = "std"), no_std)]

extern crate core;
#[cfg(not(feature = "std"))]
extern crate alloc;

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
#[cfg(all(feature = "alloc"))]
pub mod maitredescles;
#[cfg(all(feature = "alloc"))]
pub mod chiffrage_docs;

#[macro_use]
mod macros;

#[cfg(test)]
mod samples;

// Re-exports
pub use ed25519_dalek;
pub use heapless;
pub use openssl;
pub use multibase;
pub use multihash;
pub use chacha20poly1305;
pub use base64;
pub use chrono;
pub use x509_parser;
pub use rand;
pub use flate2;
