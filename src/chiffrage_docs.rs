use std::collections::BTreeMap;
use heapless::FnvIndexMap;
use crate::error::Error;
use crate::maitredescles::SignatureDomaines;
use crate::messages_structs::DechiffrageInterMillegrille;
use serde::{Deserialize, Serialize};
use crate::chiffrage_mgs4::DecipherMgs4;
use base64::{engine::general_purpose::STANDARD as base64, Engine as _};
use crate::chiffrage::{CleSecrete, FormatChiffrage, formatchiffragestr};
use crate::chiffrage_cles::{CipherResultVec, CleDechiffrageX25519Impl, Decipher};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedDocument {
    pub ciphertext_base64: std::string::String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cle_id: Option<std::string::String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compression: Option<std::string::String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cles: Option<BTreeMap<std::string::String, std::string::String>>,
    #[serde(with="formatchiffragestr")]
    pub format: FormatChiffrage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<std::string::String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureDomaines>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<std::string::String>,
}

impl EncryptedDocument {

    pub fn decrypt_with_secret(self, secret: &CleSecrete<32>) -> Result<Vec<u8>, Error> {
        let cle = CleDechiffrageX25519Impl {
            cle_chiffree: "".to_string(),
            cle_secrete: Some(secret.clone()),
            format: self.format,
            nonce: self.nonce,
            verification: self.verification,
        };
        match self.format {
            FormatChiffrage::MGS4 => {
                let decipher = DecipherMgs4::new(&cle)?;
                let data = base64.decode(self.ciphertext_base64).map_err(|e| Error::String(format!("base64 decode error: {:?}", e)))?;
                match &self.compression {
                    Some(inner) => match inner.as_str() {
                        "gz" => decipher.gz_to_vec(data.as_slice()),
                        "deflate" => decipher.deflate_to_vec(data.as_slice()),
                        _ => Err(Error::String(format!("Unsupported compression algorithm: {:?}", self.compression)))
                    },
                    None => decipher.to_vec(data.as_slice())
                }
            }
        }
    }
}

impl TryFrom<CipherResultVec<32>> for EncryptedDocument {
    type Error = Error;

    fn try_from(value: CipherResultVec<32>) -> Result<Self, Self::Error> {

        let ciphertext_base64 = base64.encode(value.ciphertext);

        let cles = if value.cles.cles_chiffrees.len() > 0 {
            let mut cles = BTreeMap::new();
            for cle in value.cles.cles_chiffrees {
                cles.insert(cle.fingerprint, cle.cle_chiffree);
            }
            Some(cles)
        } else {
            None
        };

        Ok(Self {
            ciphertext_base64,
            cle_id: None,
            compression: value.compression,
            cles,
            format: value.cles.format.clone(),
            nonce: value.cles.nonce,
            signature: None,
            verification: Some(value.hachage_bytes),
        })
    }
}

impl<'a> TryInto<DechiffrageInterMillegrille<'a>> for &'a EncryptedDocument {

    type Error = Error;

    fn try_into(self) -> Result<DechiffrageInterMillegrille<'a>, Error> {

        let cles = match &self.cles {
            Some(inner) => {
                let mut cles = FnvIndexMap::new();
                for (cle, value) in inner {
                    if let Err(_) = cles.insert(cle.as_str(), value.as_str()) {
                        Err(Error::Str("try_into Erreur TryInto<DechiffrageInterMillegrille>"))?
                    }
                }
                Some(cles)
            },
            None => None
        };

        Ok(DechiffrageInterMillegrille {
            cle_id: match &self.cle_id { Some(inner) => Some(inner.as_str()), None => None },
            cles,
            compression: match &self.compression { Some(inner) => Some(inner.as_str()), None => None },
            format: (&self.format).into(),
            hachage: None,
            header: None,
            nonce: match &self.nonce { Some(inner) => Some(inner.as_str()), None => None },
            signature: match &self.signature { Some(inner) => Some(inner.clone()), None => None },
            verification: match &self.verification { Some(inner) => Some(inner.as_str()), None => None },
        })
    }
}

#[cfg(test)]
mod chiffrage_mgs4_tests {
    use std::str::from_utf8;
    use super::*;
    use log::info;
    use crate::chiffrage_cles::Cipher;
    use crate::chiffrage_mgs4::CipherMgs4;

    const CONTENU_A_CHIFFRER: &str = "Du contenu a chiffrer";

    #[test_log::test]
    fn test_chiffrer_dechiffrer() {
        let cipher = CipherMgs4::new().unwrap();
        let chiffre = cipher.to_vec(CONTENU_A_CHIFFRER.as_bytes()).unwrap();
        info!("Ciphertext taille {}\n{}", chiffre.ciphertext.len(), base64.encode(&chiffre.ciphertext));
        let cle_secrete = chiffre.cles.cle_secrete.clone();
        let encrypted_doc = EncryptedDocument::try_from(chiffre).expect("encrypted document");
        info!("Encrypted document: {:?}", encrypted_doc);
        let resultat = encrypted_doc.decrypt_with_secret(&cle_secrete).expect("decrypt_with_secret");
        let resultat_str = from_utf8(resultat.as_slice()).unwrap();
        info!("Decrypted content: {}", resultat_str);
        assert_eq!(CONTENU_A_CHIFFRER, resultat_str);
    }

    #[test_log::test]
    fn test_chiffrer_dechiffrer_gz() {
        let cipher = CipherMgs4::new().unwrap();
        let chiffre = cipher.to_gz_vec(CONTENU_A_CHIFFRER.as_bytes()).unwrap();
        info!("Ciphertext taille {}\n{}", chiffre.ciphertext.len(), base64.encode(&chiffre.ciphertext));
        let cle_secrete = chiffre.cles.cle_secrete.clone();
        let encrypted_doc = EncryptedDocument::try_from(chiffre).expect("encrypted document");
        info!("Encrypted document: {:?}", encrypted_doc);
        let resultat = encrypted_doc.decrypt_with_secret(&cle_secrete).expect("decrypt_with_secret");
        let resultat_str = from_utf8(resultat.as_slice()).unwrap();
        info!("Decrypted content: {}", resultat_str);
        assert_eq!(CONTENU_A_CHIFFRER, resultat_str);
    }

    #[test_log::test]
    fn test_chiffrer_dechiffrer_deflate() {
        let cipher = CipherMgs4::new().unwrap();
        let chiffre = cipher.to_deflate_vec(CONTENU_A_CHIFFRER.as_bytes()).unwrap();
        info!("Ciphertext taille {}\n{}", chiffre.ciphertext.len(), base64.encode(&chiffre.ciphertext));
        let cle_secrete = chiffre.cles.cle_secrete.clone();
        let encrypted_doc = EncryptedDocument::try_from(chiffre).expect("encrypted document");
        info!("Encrypted document: {:?}", encrypted_doc);
        let resultat = encrypted_doc.decrypt_with_secret(&cle_secrete).expect("decrypt_with_secret");
        let resultat_str = from_utf8(resultat.as_slice()).unwrap();
        info!("Decrypted content: {}", resultat_str);
        assert_eq!(CONTENU_A_CHIFFRER, resultat_str);
    }
}
