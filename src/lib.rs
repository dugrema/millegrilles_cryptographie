//#![no_std]

extern crate core;

mod verification;
pub mod ed25519;
mod x25519;
pub mod hachages;
pub mod generateur;
pub mod messages_structs;
pub mod securite;

// Std features
#[cfg(feature = "std")]
pub mod x509;
#[cfg(feature = "std")]
pub mod x509_store;

pub use ed25519_dalek;
