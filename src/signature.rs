// use alloc::string::ToString;
// use multibase::{Base, encode};
// use openssl::error::ErrorStack;
// use openssl::pkey::{PKey, Private};
// use openssl::sign::Signer;

pub const VERSION_2: u8 = 0x2;

// pub fn signer_message(private_key: &PKey<Private>, message_id: &[u8]) -> Result<String, ErrorStack> {
//     // let key_size = private_key.size();
//     let mut to_bytes: [u8; 64] = [0u8; 64];
//     // to_bytes[0] = VERSION_2;  // Version 2 de la signature MilleGrilles (ed25519)
//
//     // let message_hache = hacher_bytes_vu8(message, Some(Code::Blake2b512));
//     //
//     // let mut signer = Signer::new_without_digest(&private_key).unwrap();
//     //
//     // let _resultat = signer.sign_oneshot(&mut to_bytes[1..], &message_hache[..])?;
//     //
//     // let signature_base64 = encode(Base64, to_bytes);
//     // debug!("Ok, taille signature {}\nSignature : {}\n{:02x?}", to_bytes.len(), signature_base64, to_bytes);
//     // Ok(signature_base64)
//
//     let mut signer = Signer::new_without_digest(&private_key).unwrap();
//     signer.sign_oneshot(&mut to_bytes[..], message_id)?;
//     let signature_hex = encode(Base::Base16Lower, to_bytes);
//     let signature_hex_stripped = &signature_hex[1..];
//     Ok(signature_hex_stripped.to_string())
// }
