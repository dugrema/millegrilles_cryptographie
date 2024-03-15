//#![no_std]

extern crate core;

mod verification;
pub mod ed25519;
mod x25519;
#[cfg(feature = "std")]
pub mod x509;
//#[cfg(feature = "std")]
// pub mod x509_store;
pub mod hachages;
pub mod generateur;
pub mod messages_structs;
pub mod securite;

pub use ed25519_dalek;
