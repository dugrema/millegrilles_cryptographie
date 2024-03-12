use ed25519_dalek::{SecretKey, Signature, Signer, SigningKey, Verifier, VerifyingKey};
use log::debug;
use multibase::{Base, Base::Base64, decode, encode};
// use openssl::error::ErrorStack;
// use openssl::pkey::{PKey, PKeyRef, Private, Public};
// use openssl::sign::{Signer, Verifier};
// use x509_parser::nom::AsBytes;

// // use crate::hachages::{HachageCode, hacher_bytes_into};
// // use crate::signature::VERSION_2;

struct Ed25519PrivateKey {
    signing_key: SigningKey,
    verifying_key: VerifyingKey
}

pub fn signer_into(signing_key: &SigningKey, message_id: &[u8], output: &mut [u8]) {
    let signature = signing_key.sign(message_id);
    hex::encode_to_slice(signature.to_bytes().as_slice(), output).unwrap();
}

pub fn verifier(verifying_key: &VerifyingKey, message_id: &[u8], signature: &[u8]) -> bool {
    let mut signature_unhex = [0u8; 64];
    hex::decode_to_slice(signature, &mut signature_unhex).unwrap();
    let signature = Signature::from_slice(&signature_unhex).unwrap();
    verifying_key.verify(message_id, &signature).is_ok()
}

// pub fn signer_into(private_key: &PKeyRef<Private>, message_id: &[u8], output: &mut [u8]) -> Result<(), ErrorStack> {
//     let mut to_bytes: [u8; 64] = [0u8; 64];
//     let mut signer = Signer::new_without_digest(&private_key).unwrap();
//     signer.sign_oneshot(&mut to_bytes[..], message_id)?;
//     let signature_hex = encode(Base::Base16Lower, to_bytes);
//     let signature_hex_stripped = &signature_hex[1..];
//     output.copy_from_slice(signature_hex_stripped.as_bytes());
//     Ok(())
// }

// pub fn verifier(public_key: &PKeyRef<Public>, message_id: &[u8], signature: &[u8]) -> Result<bool, ErrorStack> {
//     let mut verifier = Verifier::new_without_digest(&public_key).unwrap();
//     let resultat = verifier.verify_oneshot(signature, message_id).unwrap();
//     Ok(resultat)
// }
//
// // pub fn signer_identite(private_key: &PKey<Private>, message: &[u8]) -> Result<String, ErrorStack> {
// //     let mut to_bytes: [u8; 65] = [0u8; 65];
// //     to_bytes[0] = VERSION_2;  // Version 2 de la signature MilleGrilles (ed25519)
// //
// //     let mut hachage = [0u8; 68];
// //     hacher_bytes_into(message, HachageCode::Blake2b512, &mut hachage);
// //
// //     let mut signer = Signer::new_without_digest(&private_key).unwrap();
// //
// //     let _resultat = signer.sign_oneshot(&mut to_bytes[1..], &message_hache[..])?;
// //
// //     let signature_base64 = encode(Base64, to_bytes);
// //     debug!("signer_identite Ok, taille signature {}\nSignature : {}\n{:02x?}", to_bytes.len(), signature_base64, to_bytes);
// //     Ok(signature_base64)
// //
// //     // let mut signer = Signer::new_without_digest(&private_key).unwrap();
// //     // signer.sign_oneshot(&mut to_bytes[..], message_id)?;
// //     // let signature_hex = encode(Base::Base16Lower, to_bytes);
// //     // let signature_hex_stripped = &signature_hex[1..];
// //     // Ok(signature_hex_stripped.to_string())
// // }
//
#[cfg(test)]
mod ed25519_tests {
    use core::str::from_utf8;
    use ed25519_dalek::SigningKey;
    use super::*;

    use hex;

    #[test]
    fn test_signer_into() {
        let data_str = "7497da22a374d7ab092b8a6fa89709739f3fe0d07921a738d376079d4632a102";
        let mut data_bytes = [0u8; 32];
        hex::decode_to_slice(data_str, &mut data_bytes).unwrap();
        let mut signature = [0u8; 128];

        // Charger private key
        let signing_key = SigningKey::from_bytes(b"01234567890123456789012345678901");
        let verifying_key = signing_key.verifying_key();

        signer_into(&signing_key, &data_bytes, &mut signature);
        let signature_str = from_utf8(&signature).unwrap();
        assert_eq!("c532ba9f1ab2c19eea526baf5c865c98894c4fa06952987192e815a5c000357437bd6d6faa95423b6264fcf9dc0e2019294c9f9dc501261e7324ecf2603b2e0f", signature_str);

        // Verifier
        let resultat = verifier(&verifying_key, &data_bytes, &signature);
        assert!(resultat);
    }
}