use flate2::Compression;
use flate2::write::GzEncoder;
use flate2::read::GzDecoder;
use std::io::{Read, Write};
use log::{debug, info};
use multibase::Base;
use openssl::pkey::{Id, PKey, Private};
use serde::{Deserialize, Serialize};

use crate::chiffrage::{CleSecrete, FormatChiffrage};
use crate::error::Error;
use crate::x25519::{chiffrer_asymmetrique_ed25519, convertir_public_ed25519_to_x25519_openssl, dechiffrer_asymmetrique_ed25519};
use crate::x509::EnveloppeCertificat;

const X25519_KEY_LEN: usize = 32;

trait CleDechiffrage<const C: usize> {
    fn cle_chiffree(&self) -> &str;
    fn cle_secrete(&self) -> Option<&CleSecrete<C>>;
    fn format(&self) -> FormatChiffrage;
    fn nonce(&self) -> Option<&String>;
    fn verification(&self) -> Option<&String>;
}

trait CleDechiffrageX25519: CleDechiffrage<X25519_KEY_LEN> {
    fn dechiffrer_x25519(&mut self, cle_dechiffrage: &PKey<Private>) -> Result<(), Error>;
}

pub struct CleDechiffrageStruct<const C: usize> {
    /// Cle chiffree encodee en multibase.
    pub cle_chiffree: String,

    /// Cle secrete dechiffree.
    pub cle_secrete: Option<CleSecrete<C>>,

    /// Format de chiffrage.
    pub format: FormatChiffrage,

    /// Nonce ou header selon l'algorithme.
    pub nonce: Option<String>,

    /// Element de verification selon le format de chiffrage.
    /// Peut etre un hachage (e.g. blake2s) ou un HMAC (e.g. compute tag de chacha20-poly1305).
    pub verification: Option<String>,
}

impl<const C: usize> CleDechiffrage<C> for CleDechiffrageStruct<C> {
    fn cle_chiffree(&self) -> &str { self.cle_chiffree.as_str() }
    fn cle_secrete(&self) -> Option<&CleSecrete<C>> { self.cle_secrete.as_ref() }
    fn format(&self) -> FormatChiffrage { self.format.clone() }
    fn nonce(&self) -> Option<&String> { self.nonce.as_ref() }
    fn verification(&self) -> Option<&String> { self.verification.as_ref() }
}

fn dechiffrer_x25519(cle: &mut CleDechiffrageStruct<X25519_KEY_LEN>, cle_dechiffrage: &PKey<Private>) -> Result<(), Error> {
    let cle_chiffree_vec = match multibase::decode(&cle.cle_chiffree) {
        Ok(inner) => inner.1,
        Err(e) => Err(Error::Multibase(e))?
    };

    let cle_dechiffree = dechiffrer_asymmetrique_ed25519(cle_chiffree_vec.as_slice(), cle_dechiffrage)?;
    cle.cle_secrete = Some(cle_dechiffree);

    Ok(())
}

pub type CleDechiffrageX25519Impl = CleDechiffrageStruct<X25519_KEY_LEN>;

impl CleDechiffrageX25519 for CleDechiffrageX25519Impl {
    fn dechiffrer_x25519(&mut self, cle_dechiffrage: &PKey<Private>) -> Result<(), Error> {
        dechiffrer_x25519(self, cle_dechiffrage)
    }
}

/// Structure qui conserve une cle chiffree pour un fingerprint de certificat
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FingerprintCleChiffree {
    /// Fingerprint du certificat correspondant a la cle chiffree.
    pub fingerprint: String,
    /// Cle chiffree encodee en multibase
    pub cle_chiffree: String,
}

trait CleChiffrage {
    fn cles_chiffrees(&self) -> &Vec<FingerprintCleChiffree>;
    fn format(&self) -> FormatChiffrage;
    fn nonce(&self) -> Option<&String>;
    fn verification(&self) -> Option<&String>;
}

trait CleChiffrageX25519: CleChiffrage {
    fn chiffrer_x25519(&mut self, cles_publiques: Vec<&EnveloppeCertificat>) -> Result<(), Error>;
}

/// Utilise pour chiffrer une cle secrete avec une ou plusieurs cles publiques (asymetrique).
pub struct CleChiffrageStruct<const K: usize> {
    /// Cle secrete dechiffree.
    pub cle_secrete: CleSecrete<K>,

    /// Cle chiffree encodee en multibase.
    pub cles_chiffrees: Vec<FingerprintCleChiffree>,

    /// Format de chiffrage.
    pub format: FormatChiffrage,

    /// Nonce ou header selon l'algorithme.
    pub nonce: Option<String>,

    /// Element de verification selon le format de chiffrage.
    /// Peut etre un hachage (e.g. blake2s) ou un HMAC (e.g. compute tag).
    pub verification: Option<String>,
}

impl<const C: usize> CleChiffrage for CleChiffrageStruct<C> {
    fn cles_chiffrees(&self) -> &Vec<FingerprintCleChiffree> { &self.cles_chiffrees }
    fn format(&self) -> FormatChiffrage { self.format.clone() }
    fn nonce(&self) -> Option<&String> { self.nonce.as_ref() }
    fn verification(&self) -> Option<&String> { self.verification.as_ref() }
}

pub type CleChiffrageX25519Impl = CleChiffrageStruct<X25519_KEY_LEN>;

impl CleChiffrageX25519 for CleChiffrageX25519Impl {
    fn chiffrer_x25519(&mut self, cles_publiques: Vec<&EnveloppeCertificat>) -> Result<(), Error> {
        for cle in cles_publiques {
            // Recuperer cle publique Ed25519
            let pubkey_ed25519 = cle.pubkey()?;
            if pubkey_ed25519.len() != X25519_KEY_LEN {
                Err(Error::Str("CleChiffrageX25519Impl::chiffrer_x25519 Taille cle publique incorrecte - doit etre 32 bytes"))?
            }

            // Convertir en X25519
            let cle_ed25519_openssl = PKey::public_key_from_raw_bytes(pubkey_ed25519.as_slice(), Id::ED25519)?;
            let cle_x25519_openssl = convertir_public_ed25519_to_x25519_openssl(&cle_ed25519_openssl)?;

            // Chiffrer la cle secrete
            let secret_chiffre = chiffrer_asymmetrique_ed25519(&self.cle_secrete.0, &cle_x25519_openssl)?;

            // Encoder en multibase base64
            let secret_chiffre_string = multibase::encode(Base::Base64, &secret_chiffre);

            // Ajouter au Vec
            let fingerprint = cle.fingerprint()?;
            self.cles_chiffrees.push(FingerprintCleChiffree {fingerprint, cle_chiffree: secret_chiffre_string} );
        }
        Ok(())
    }
}

pub struct CipherResult<const K: usize> {
    pub len: usize,
    pub cles: CleChiffrageStruct<K>,
    pub hachage_bytes: String,
}

pub struct CipherResultVec<const K: usize> {
    pub ciphertext: std::vec::Vec<u8>,
    pub cles: CleChiffrageStruct<K>,
    pub hachage_bytes: String,
}

pub trait Cipher<const K: usize> {
    fn update(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, Error>;

    fn finalize(self, out: &mut [u8]) -> Result<CipherResult<K>, Error>;

    /// Chiffre le data.
    fn to_vec(mut self, data: &[u8]) -> Result<CipherResultVec<K>, Error>
        where Self: Sized
    {
        let mut ciphertext = std::vec::Vec::new();

        // Taille pour mgs4 : 17 bytes par block de 64kb (0.0003) + 17 bytes
        let taille_reserver = (data.len() as f64 * 1.0003 + 17f64) as usize;
        ciphertext.reserve(taille_reserver);
        ciphertext.extend(std::iter::repeat(0u8).take(taille_reserver));

        let taille = self.update(data, ciphertext.as_mut_slice())?;
        let resultat = self.finalize(&mut ciphertext.as_mut_slice()[taille..])?;
        let taille_totale = taille + resultat.len;
        ciphertext.truncate(taille_totale);

        Ok(CipherResultVec {
            ciphertext,
            cles: resultat.cles,
            hachage_bytes: resultat.hachage_bytes
        })
    }

    /// Compresse le data avec Gzip avant de chiffrer.
    fn to_gz_vec(mut self, data: &[u8]) -> Result<CipherResultVec<K>, Error>
        where Self: Sized
    {
        // Compresser bytes
        let data_vec = {
            let mut compressor = GzEncoder::new(std::vec::Vec::new(), Compression::default());
            compressor.write_all(data)?;
            compressor.finish()?
        };

        self.to_vec(data_vec.as_slice())
    }
}

pub trait Decipher {
    fn update(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, Error>;

    fn finalize(self, out: &mut [u8]) -> Result<usize, Error>;

    fn to_vec(mut self, data: &[u8]) -> Result<Vec<u8>, Error>
        where Self: Sized
    {
        let mut output_decipher = std::vec::Vec::new();
        output_decipher.reserve(data.len());
        output_decipher.extend(std::iter::repeat(1u8).take(data.len()));

        let cleartext_len = self.update(data, output_decipher.as_mut()).unwrap();
        let decipher_finalize_len = self.finalize(&mut output_decipher.as_mut_slice()[cleartext_len..]).unwrap();

        let taille_decipher_totale = cleartext_len + decipher_finalize_len;
        output_decipher.truncate(taille_decipher_totale);

        Ok(output_decipher)
    }

    fn gz_to_vec(mut self, data: &[u8]) -> Result<Vec<u8>, Error>
        where Self: Sized
    {
        let vec_dechiffre = self.to_vec(data)?;
        let mut decoder = GzDecoder::new(vec_dechiffre.as_slice());
        let mut data_decompresse = Vec::new();
        decoder.read_to_end(&mut data_decompresse)?;
        Ok(data_decompresse)
    }
}
