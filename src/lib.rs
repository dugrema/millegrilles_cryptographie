// #![no_std]

extern crate core;

pub mod ed25519;
pub mod hachages;
pub mod generateur;
pub mod messages_structs;
pub mod securite;

// Std features
#[cfg(feature = "x509")]
pub mod x509;
#[cfg(feature = "x509")]
pub mod x509_store;
#[cfg(all(feature = "openssl", feature = "dryoc", feature = "x25519"))]
pub mod x25519;
#[cfg(all(feature = "openssl", feature = "dryoc", feature = "x25519"))]
pub mod chiffrage_mgs4;
#[cfg(all(feature = "openssl", feature = "dryoc", feature = "x25519"))]
pub mod chiffrage_cles;
mod chiffrage;

pub use ed25519_dalek;
