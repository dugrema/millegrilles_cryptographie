// Pour unit tests avec std, commenter ligne suivante et ajouter --features stc
#![cfg_attr(test, no_std)]
//#![no_std]

extern crate core;

pub mod verification;
mod ed25519;
mod x25519;
mod x509;
mod hachages;
mod generateur;
mod messages_structs;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}
