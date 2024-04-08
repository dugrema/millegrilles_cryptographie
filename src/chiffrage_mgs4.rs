use std::cmp::min;
use dryoc::classic::crypto_secretstream_xchacha20poly1305::*;
use dryoc::constants::{
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL,
    CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE
};
use log::debug;
use multibase::{Base, encode};

use crate::chiffrage::{CleSecrete, FormatChiffrage};
use crate::chiffrage_cles::{Cipher, CipherResult, CleChiffrageStruct, CleChiffrageX25519Impl, CleDechiffrageX25519Impl, Decipher, FingerprintCleChiffree};
use crate::error::Error;
use crate::hachages::{HacheurBlake2b512, HacheurInterne, HachageMultihash};
use crate::x25519::{CleDerivee, CleSecreteX25519, deriver_asymetrique_ed25519};
use crate::x509::EnveloppeCertificat;

const CONST_TAILLE_BLOCK_MGS4: usize = 64 * 1024;

#[derive(Clone)]
pub enum CleSecreteCipher {
    CleDerivee((String, CleDerivee)),   // Fingerprint, CleDerivee
    CleSecrete(CleSecreteX25519)        // Cle secrete
}

pub struct ResultatChiffrage {
    pub cle: CleChiffrageX25519Impl,
    pub taille: usize,
    pub hachage_bytes: String,
}

/// Implementation mgs4
pub struct CipherMgs4 {
    state: State,
    header: String,
    hacheur: HacheurBlake2b512,
    buffer: [u8; CONST_TAILLE_BLOCK_MGS4-CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES],  // Buffer de chiffrage
    position_buffer: usize,
    cle_secrete: CleSecreteCipher,
}

impl CipherMgs4 {
    pub fn new() -> Result<Self, Error> {
        // Generer une nouvelle cle secrete
        let cle_secrete = CleSecrete::generer();

        Self::with_secret(CleSecreteCipher::CleSecrete(cle_secrete))
    }

    pub fn with_ca(ca: &EnveloppeCertificat) -> Result<Self, Error> {
        if !ca.est_ca()? {
            Err(Error::Str("Le certificat n'est pas CA"))?
        }

        // Generer une cle secrete
        let cle_derivee = deriver_asymetrique_ed25519(&ca.certificat.public_key()?)?;

        Self::with_secret(CleSecreteCipher::CleDerivee((ca.fingerprint()?, cle_derivee)))
    }

    pub fn with_secret<C>(cle: C) -> Result<Self, Error>
        where C: Into<CleSecreteCipher>
    {
        let cle = cle.into();

        let cle_secrete = match &cle {
            CleSecreteCipher::CleDerivee((_, cle)) => &cle.secret,
            CleSecreteCipher::CleSecrete(cle) => cle
        };

        let mut state = State::new();
        let mut header = Header::default();
        let key = Key::from(cle_secrete.0);
        crypto_secretstream_xchacha20poly1305_init_push(&mut state, &mut header, &key);

        Ok(Self {
            state,
            header: encode(Base::Base64, header),
            hacheur: HacheurBlake2b512::new(),
            buffer: [0u8; CONST_TAILLE_BLOCK_MGS4 - CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES],
            position_buffer: 0,
            cle_secrete: cle
        })
    }
}

impl Cipher<32> for CipherMgs4 {

    fn update(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        let mut position_data: usize = 0;
        let mut position_output: usize = 0;

        // Taille du block de lecture de data (enlever 17 bytes overhead au block cipher)
        const TAILLE_BLOCK_DATA: usize = CONST_TAILLE_BLOCK_MGS4 - CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;

        while position_data < data.len() {
            // Dechiffrer un block de donnees
            let taille_data_restante = data.len() - position_data;
            debug!("CipherMgs<Mgs4CipherKeys>.update position_data {}, data.len {}, taille_data_restante {}", position_data, data.len(), taille_data_restante);

            // Copier chunk dans le buffer
            let taille_max = TAILLE_BLOCK_DATA - self.position_buffer;  // Max espace restant dans buffer
            let taille_chunk = min(taille_data_restante, taille_max);
            self.buffer[self.position_buffer..self.position_buffer+taille_chunk].copy_from_slice(&data[position_data..position_data+taille_chunk]);
            self.position_buffer += taille_chunk;
            position_data += taille_chunk;

            // Verifier si on fait un output
            if self.position_buffer == TAILLE_BLOCK_DATA {
                let slice_output = &mut out[position_output..position_output+CONST_TAILLE_BLOCK_MGS4];

                crypto_secretstream_xchacha20poly1305_push(
                    &mut self.state, slice_output, &self.buffer, None, CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE)?;

                self.position_buffer = 0;  // Reset position buffer
                position_output += CONST_TAILLE_BLOCK_MGS4;
            }

        }

        if position_output > 0 {
            self.hacheur.update(&out[..position_output]);
        }

        Ok(position_output)
    }

    fn finalize(mut self, out: &mut [u8]) -> Result<CipherResult<32>, Error> {
        let taille_output = self.position_buffer + CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;
        let slice_output = &mut out[..taille_output];

        crypto_secretstream_xchacha20poly1305_push(
            &mut self.state,
            slice_output,
            &self.buffer[..self.position_buffer],
            None,
            CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL,
        )?;

        self.hacheur.update(slice_output);

        // Calculer et conserver hachage
        let hachage_bytes = self.hacheur.finalize_mh(Base::Base58Btc)?;

        let (cle_secrete, cles_chiffrees) = match self.cle_secrete {
            CleSecreteCipher::CleDerivee((fingerprint, cle_derivee)) => {
                // Encoder la cle derivee (peer)
                let peer_string = multibase::encode(Base::Base64, cle_derivee.public_peer);
                (cle_derivee.secret, vec![FingerprintCleChiffree {fingerprint, cle_chiffree: peer_string}])
            },
            CleSecreteCipher::CleSecrete(cle) => {
                // Retourner la cle secrete. Aucuns peers/cles publiques.
                (cle, vec![])
            }
        };

        let cles = CleChiffrageStruct {
            cle_secrete,
            cles_chiffrees,
            format: FormatChiffrage::MGS4,
            nonce: Some(self.header),
            verification: None,
        };

        Ok(CipherResult {
            len: taille_output,
            cles,
            hachage_bytes
        })
    }

}

pub struct DecipherMgs4 {
    state: State,
    // header: [u8; 24],
    buffer: [u8; CONST_TAILLE_BLOCK_MGS4],
    position_buffer: usize,
}

impl DecipherMgs4 {
    pub fn new(decipher_data: &CleDechiffrageX25519Impl) -> Result<Self, Error> {
        match decipher_data.format {
            FormatChiffrage::MGS4 => (),
            // _ => Err(Error::Str("Format de dechiffrage doit etre MGS4"))?
        }

        let cle_dechiffree = match &decipher_data.cle_secrete {
            Some(inner) => inner,
            None => Err(Error::Str("Cle secrete manquante"))?
        };

        let header_vec = match &decipher_data.nonce {
            Some(inner) => match multibase::decode(inner) {
                Ok(inner) => inner.1,
                Err(e) => Err(Error::Multibase(e))?
            },
            None => Err(Error::Str("Compute tag (verification) manquant"))?
        };

        let mut state = State::new();
        let key = Key::from(cle_dechiffree.0);
        let mut header: Header = Header::default();
        header.copy_from_slice(&header_vec[0..24]);
        crypto_secretstream_xchacha20poly1305_init_pull(&mut state, &header, &key);

        Ok(DecipherMgs4 { state, buffer: [0u8; CONST_TAILLE_BLOCK_MGS4], position_buffer: 0 })
    }
}

impl Decipher for DecipherMgs4 {

    fn update(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, Error> {

        let mut position_data: usize = 0;
        let mut position_output: usize = 0;

        while position_data < data.len() {

            // Dechiffrer un block de donnees
            let taille_data_restante = data.len() - position_data;

            // Copier chunk dans le buffer
            let taille_max = CONST_TAILLE_BLOCK_MGS4 - self.position_buffer;  // Max espace restant dans buffer
            let taille_chunk = min(taille_data_restante, taille_max);
            self.buffer[self.position_buffer..self.position_buffer+taille_chunk].copy_from_slice(&data[position_data..position_data+taille_chunk]);
            self.position_buffer += taille_chunk;
            position_data += taille_chunk;

            // Verifier si on fait un output
            if self.position_buffer == CONST_TAILLE_BLOCK_MGS4 {
                const TAILLE_OUTPUT: usize = CONST_TAILLE_BLOCK_MGS4 - CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;
                let slice_output = &mut out[position_output..position_output+TAILLE_OUTPUT];
                let mut output_tag = 0u8;

                let _result = crypto_secretstream_xchacha20poly1305_pull(
                    &mut self.state, slice_output, &mut output_tag, &self.buffer, None)?;

                if output_tag != CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE {
                    Err(Error::Str("DecipherMgs4.finalize Erreur block final mauvais tag"))?
                }

                self.position_buffer = 0;  // Reset position buffer
                position_output += TAILLE_OUTPUT;
            }

        }

        Ok(position_output)
    }

    fn finalize(mut self, out: &mut [u8]) -> Result<usize, Error> {

        if self.position_buffer < CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES {
            Err(Error::Str("DecipherMgs4.finalize Erreur block final < 17 bytes"))?
        }

        let taille_output = self.position_buffer - CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;

        let mut output_tag = 0u8;

        let ciphertext = &self.buffer[0..self.position_buffer];
        debug!("DecipherMgs4.finalize dechiffrage de ciphertext {:?}", ciphertext);

        // Dechiffrer
        let _taille_finale = crypto_secretstream_xchacha20poly1305_pull(
            &mut self.state, out, &mut output_tag, ciphertext, None)?;

        if output_tag != CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL {
            Err(Error::Str("DecipherMgs4.finalize Erreur block final mauvais tag"))?
        }

        Ok(taille_output)
    }
}

#[cfg(test)]
mod chiffrage_mgs4_tests {
    use std::str::from_utf8;
    use super::*;
    use log::info;
    use crate::chiffrage_cles::CleDechiffrageStruct;

    const CONTENU_A_CHIFFRER: &str = "Du contenu a chiffrer";

    #[test_log::test]
    fn test_chiffrer_dechiffrer() {
        // Chiffrer
        let cipher = CipherMgs4::new().unwrap();
        let chiffre = cipher.to_vec(CONTENU_A_CHIFFRER.as_bytes()).unwrap();
        info!("Ciphertext taille {}\n{}", chiffre.ciphertext.len(), encode(Base::Base64, &chiffre.ciphertext));

        // Convertir le result en cle de dechiffrage
        let cle_chiffrage = chiffre.cles;
        let cle_dechiffrage = CleDechiffrageStruct {
            cle_chiffree: "NA".to_string(),
            cle_secrete: Some(cle_chiffrage.cle_secrete),
            format: cle_chiffrage.format,
            nonce: cle_chiffrage.nonce,
            verification: None,
        };

        // Dechiffrer
        let ciphertext = chiffre.ciphertext;
        let decipher = DecipherMgs4::new(&cle_dechiffrage).unwrap();
        let dechiffre = decipher.to_vec(ciphertext.as_slice()).unwrap();

        let output_decipher_str = from_utf8(dechiffre.as_slice()).unwrap();
        info!("Decipher len {}, contenu\n{}", dechiffre.len(), output_decipher_str);
        assert_eq!(CONTENU_A_CHIFFRER.len(), dechiffre.len());
    }

    #[test_log::test]
    fn test_chiffrer_dechiffrer_gz() {
        let cipher = CipherMgs4::new().unwrap();
        let chiffre = cipher.to_gz_vec(CONTENU_A_CHIFFRER.as_bytes()).unwrap();
        info!("Ciphertext taille {}\n{}", chiffre.ciphertext.len(), encode(Base::Base64, &chiffre.ciphertext));

        // Convertir le result en cle de dechiffrage
        let cle_chiffrage = chiffre.cles;
        let cle_dechiffrage = CleDechiffrageStruct {
            cle_chiffree: "NA".to_string(),
            cle_secrete: Some(cle_chiffrage.cle_secrete),
            format: cle_chiffrage.format,
            nonce: cle_chiffrage.nonce,
            verification: None,
        };

        // Dechiffrer
        let ciphertext = chiffre.ciphertext;
        let decipher = DecipherMgs4::new(&cle_dechiffrage).unwrap();
        let dechiffre = decipher.gz_to_vec(ciphertext.as_slice()).unwrap();

        let output_decipher_str = from_utf8(dechiffre.as_slice()).unwrap();
        info!("Decipher len {}, contenu\n{}", dechiffre.len(), output_decipher_str);
        assert_eq!(CONTENU_A_CHIFFRER.len(), dechiffre.len());
    }

}
