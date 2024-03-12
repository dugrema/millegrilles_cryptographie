// Pour unit tests avec std, commenter ligne suivante et ajouter --features stc
//#![cfg_attr(test, no_std)]
#![no_std]

extern crate alloc;
extern crate core;

pub mod signature;
pub mod verification;
mod ed25519;
mod x25519;
mod x509;
mod hachages;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
