// use std::error::Error;
// use log::debug;
// use multibase::decode;
// use openssl::pkey::{PKey, Public};
// use openssl::sign::Verifier;
// use crate::hachages::hacher_bytes_vu8;
// use crate::signature::VERSION_2;
//
// pub fn verifier_message(public_key: &PKey<Public>, message: &[u8], signature: &str) -> Result<bool, Box<dyn Error>> {
//
//     let (_, sign_bytes): (_, Vec<u8>) = decode(signature)?;
//     let type_sign = &sign_bytes[0];
//     let signature_bytes = &sign_bytes[1..];
//
//     debug!("Verifier signature type {:?} / {:?} avec public key {:?}", type_sign, signature_bytes, public_key);
//
//     if *type_sign != VERSION_2 {
//         debug!("Version signature est {:?}, devrait etre 2", type_sign);
//         Err(format!("La version de la signature n'est pas 2"))?;
//     }
//
//     let message_hache = hacher_bytes_vu8(message, Some(Code::Blake2b512));
//
//     let mut verifier = Verifier::new_without_digest(&public_key)?;
//     // let resultat = verifier.verify_oneshot(signature_bytes, &message[0..10])?;
//     let resultat = verifier.verify_oneshot(signature_bytes, &message_hache[..])?;
//
//     Ok(resultat)
// }
