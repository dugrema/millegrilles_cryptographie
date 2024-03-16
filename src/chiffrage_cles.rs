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
pub struct CleChiffrageStruct<const C: usize> {
    /// Cle secrete dechiffree.
    pub cle_secrete: CleSecrete<C>,

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
