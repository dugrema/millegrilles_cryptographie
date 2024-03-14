use alloc::string::ToString;
use core::str::from_utf8;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

struct Ed25519PrivateKey {
    signing_key: SigningKey,
    verifying_key: VerifyingKey
}

pub type MessageId = [u8; 32];

pub fn signer_into<'a>(signing_key: &SigningKey, message_id: &MessageId, output_str: &'a mut [u8; 128]) -> &'a str {
    let signature = signing_key.sign(message_id);
    hex::encode_to_slice(signature.to_bytes().as_slice(), output_str).unwrap();
    from_utf8(output_str).unwrap()
}

#[cfg(feature = "std")]
pub fn signer(signing_key: &SigningKey, message_id: &str) -> String {
    let mut buffer = [0u8; 128];
    let mut message_id_bytes = [0u8; 32] as MessageId;
    message_id_bytes.copy_from_slice(hex::decode(message_id).unwrap().as_slice());
    let signature_str = signer_into(signing_key, &message_id_bytes, &mut buffer);
    signature_str.to_string()
}

pub fn verifier(verifying_key: &VerifyingKey, message_id: &MessageId, signature: &str) -> bool {
    let mut signature_unhex = [0u8; 64];
    hex::decode_to_slice(signature, &mut signature_unhex).unwrap();
    let signature = Signature::from_slice(&signature_unhex).unwrap();
    verifying_key.verify(message_id, &signature).is_ok()
}

#[cfg(test)]
mod ed25519_tests {
    use ed25519_dalek::SigningKey;
    use super::*;

    use hex;

    #[test]
    fn test_signer_into() {
        let data_str = "7497da22a374d7ab092b8a6fa89709739f3fe0d07921a738d376079d4632a102";
        let mut data_bytes = [0u8; 32];
        hex::decode_to_slice(data_str, &mut data_bytes).unwrap();

        // Charger private key
        let signing_key = SigningKey::from_bytes(b"01234567890123456789012345678901");
        let verifying_key = signing_key.verifying_key();

        let mut signature_buffer = [0u8; 128];
        let signature_str = signer_into(&signing_key, &data_bytes, &mut signature_buffer);
        assert_eq!("c532ba9f1ab2c19eea526baf5c865c98894c4fa06952987192e815a5c000357437bd6d6faa95423b6264fcf9dc0e2019294c9f9dc501261e7324ecf2603b2e0f", signature_str);

        // Verifier
        let resultat = verifier(&verifying_key, &data_bytes, &signature_str);
        assert!(resultat);

        // Signature corrompue
        let signature_invalide_str = "c532ba9f1ab2c19eea526baf5c865c98894c4fa06952987192e815a5c000357437bd6d6faa95423b6264fcf9dc0e2019294c9f9dc501261e7324ecf2603b2e0a";
        let resultat = verifier(&verifying_key, &data_bytes, &signature_invalide_str);
        assert!(!resultat);
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_signer_verifier() {
        let data_str = "7497da22a374d7ab092b8a6fa89709739f3fe0d07921a738d376079d4632a102";
        let mut data_bytes = [0u8; 32] as MessageId;
        data_bytes.copy_from_slice(hex::decode(data_str).unwrap().as_slice());

        // Charger private key
        let signing_key = SigningKey::from_bytes(b"01234567890123456789012345678901");
        let verifying_key = signing_key.verifying_key();

        let signature_string = signer(&signing_key, &data_str);
        assert_eq!("c532ba9f1ab2c19eea526baf5c865c98894c4fa06952987192e815a5c000357437bd6d6faa95423b6264fcf9dc0e2019294c9f9dc501261e7324ecf2603b2e0f", signature_string.as_str());

        // Verifier
        let resultat = verifier(&verifying_key, &data_bytes, signature_string.as_str());
        assert!(resultat);

        // Signature corrompue
        let signature_invalide_str = "c532ba9f1ab2c19eea526baf5c865c98894c4fa06952987192e815a5c000357437bd6d6faa95423b6264fcf9dc0e2019294c9f9dc501261e7324ecf2603b2e0a";
        let resultat = verifier(&verifying_key, &data_bytes, &signature_invalide_str);
        assert!(!resultat);
    }
}
