use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305};
use dryoc::classic::crypto_sign_ed25519;
use openssl::derive::Deriver;
use openssl::pkey::{Id, PKey, Private, Public};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::chiffrage::CleSecrete;
use crate::error::Error;
use crate::hachages::{HachageCode, hacher_bytes_into};

pub type ClePubliqueX25519 = [u8; 32];

pub type CleSecreteX25519 = CleSecrete<32>;

/// Format d'une cle asymmetrique. Le premier byte des version 3+ represent la version du format.
/// Pour les versions 1 et 2, on se fie a la taille de la cle.
#[derive(Clone, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum FormatCleAsymmetrique {
    /// 32 bytes, un public peer pour le CA
    CleDeriveeV1 = 1,
    /// 80 bytes : |public peer: 32 bytes|cle chiffree XChacha20 : 32 bytes|compute tag : 16 bytes|
    CleChiffreeV1 = 2,
    /// 33 bytes : |Version: 1 byte|public peer CA: 32 bytes|
    CleDeriveeV2 = 3,
    /// 93 bytes : |Version: 1 byte|public peer: 32 bytes|nonce: 12 bytes|cle chiffree XChacha20 : 32 bytes|compute tag: 16 bytes|
    CleChiffreeV2 = 4
}

impl FormatCleAsymmetrique {
    pub fn detecter_version(cle_secrete: &[u8]) -> Result<Self, Error> {
        match cle_secrete.len() {
            32 => Ok(Self::CleDeriveeV1),
            80 => Ok(Self::CleChiffreeV1),
            _ => {
                let version_byte = cle_secrete[0];
                Ok(serde_json::from_slice(&[version_byte])?)
            }
        }
    }
}

#[derive(Clone)]
pub struct CleDerivee {
    pub secret: CleSecreteX25519,
    pub public_peer: ClePubliqueX25519,
}

/**
Derive une cle secrete a partir d'une cle publique. Utiliser avec cle publique du cert CA.
Retourne : (secret key, public peer)
 */
pub fn deriver_asymetrique_ed25519(public_key: &PKey<Public>) -> Result<CleDerivee, Error> {

    if public_key.id() != Id::ED25519 {
        Err(Error::Str("deriver_asymetrique_ed25519 Mauvais type de cle publique, doit etre ED25519"))?
    }

    let cle_peer = match PKey::generate_x25519() {
        Ok(inner) => inner,
        Err(e) => Err(Error::Openssl(e))?
    };
    let public_peer = {
        let mut pk = [0u8; 32];
        let raw_pk = match cle_peer.raw_public_key() {
            Ok(inner) => inner,
            Err(e) => Err(Error::Openssl(e))?
        };
        pk.copy_from_slice(&raw_pk[..]);
        pk
    };

    // Convertir cle CA publique Ed25519 en X25519
    let cle_public_x25519 = convertir_public_ed25519_to_x25519_openssl(public_key)?;

    let mut deriver = match Deriver::new(&cle_peer) {
        Ok(inner) => inner,
        Err(e) => Err(Error::Openssl(e))?
    };
    if let Err(e) = deriver.set_peer(cle_public_x25519.as_ref()) {
        Err(Error::Openssl(e))?
    }
    let mut cle_secrete = [0u8; 32];
    if let Err(e) = deriver.derive(&mut cle_secrete) {
        Err(Error::Openssl(e))?
    }

    // Hacher la cle avec blake2s-256
    let mut cle_hachee = [0u8; 32];  // 32 bytes Blake2s
    hacher_bytes_into(&cle_secrete[..], HachageCode::Blake2s256, &mut cle_hachee);
    cle_secrete.copy_from_slice(&cle_hachee[0..32]); // Override cle secrete avec version hachee

    Ok(CleDerivee {secret: CleSecrete(cle_secrete), public_peer})
}

/**
Rederive une cle secrete a partir d'une cle publique et cle privee.
 */
pub fn deriver_asymetrique_ed25519_peer(peer_x25519: &PKey<Public>, private_key_in: &PKey<Private>) -> Result<CleSecreteX25519, Error> {

    if peer_x25519.id() != Id::X25519 {
        Err(Error::Str("deriver_asymetrique_ed25519_peer Mauvais type de cle publique, doit etre X25519"))?
    }

    // Convertir cle privee en format X25519
    let cle_privee_pkey = match private_key_in.id() {
        Id::X25519 => private_key_in.to_owned(),
        Id::ED25519 => convertir_private_ed25519_to_x25519(private_key_in)?,
        _ => Err(Error::Str("deriver_asymetrique_ed25519_peer Mauvais type de cle private, doit etre ED25519 ou X25519"))?
    };

    let mut deriver = match Deriver::new(&cle_privee_pkey) {
        Ok(inner) => inner,
        Err(e) => Err(Error::Openssl(e))?
    };
    if let Err(e) = deriver.set_peer(peer_x25519) {
        Err(Error::Openssl(e))?
    }
    let mut cle_secrete = [0u8; 32];
    if let Err(e) = deriver.derive(&mut cle_secrete) {
        Err(Error::Openssl(e))?
    }

    // Hacher la cle avec blake2s-256
    let mut cle_hachee = [0u8; 32];  // 32 bytes Blake2s
    hacher_bytes_into(&cle_secrete[..], HachageCode::Blake2s256, &mut cle_hachee);
    cle_secrete.copy_from_slice(&cle_hachee[0..32]); // Override cle secrete avec version hachee

    Ok(CleSecrete(cle_secrete))
}

pub fn chiffrer_asymmetrique_ed25519(cle_secrete: &[u8], cle_publique: &PKey<Public>) -> Result<[u8; 80], Error> {

    let cle_publique_x25519 = convertir_public_ed25519_to_x25519_openssl(cle_publique)?;
    let cle_peer = match PKey::generate_x25519() {
        Ok(inner) => inner,
        Err(e) => Err(Error::Openssl(e))?
    };
    let cle_peer_public_raw = match cle_peer.raw_public_key() {
        Ok(inner) => inner,
        Err(e) => Err(Error::Openssl(e))?
    };

    // Trouver cle secrete de dechiffrage de la cle privee
    let cle_secrete_intermediaire = deriver_asymetrique_ed25519_peer(&cle_publique_x25519, &cle_peer)?;

    // Utiliser chacha20poly1305 pour dechiffrer la cle secrete
    let aead = ChaCha20Poly1305::new(cle_secrete_intermediaire.0[..].into());

    // Note : on utilise la cle publique du peer (valeur random) hachee en blake2s comme nonce (12 bytes) pour le chiffrage
    let mut nonce = [0u8; 32];  // 32 bytes Blake2s
    hacher_bytes_into(&cle_peer_public_raw[..], HachageCode::Blake2s256, &mut nonce);
    let cle_secrete_chiffree_tag = match aead.encrypt(nonce[0..12].into(), cle_secrete.as_ref()) {
        Ok(m) => m,
        Err(e) => Err(Error::Chacha20poly1350(e))?
    };

    let mut vec_resultat = Vec::new();
    vec_resultat.extend_from_slice(&cle_peer_public_raw[..]);  // 32 bytes cle publique peer
    vec_resultat.extend_from_slice(&cle_secrete_chiffree_tag[..]);  // 32 cle secrete chiffree + 16 bytes auth tag

    let mut resultat = [0u8; 80];
    resultat.copy_from_slice(&vec_resultat[..]);

    Ok(resultat)
}

pub fn dechiffrer_asymmetrique_ed25519(cle_chiffree: &[u8], cle_privee: &PKey<Private>) -> Result<CleSecreteX25519, Error> {

    // Verifier si la cle est 32 bytes (dechiffrage avec cle de millegrille) ou 80 bytes (standard)
    if cle_chiffree.len() != 32 && cle_chiffree.len() != 80 {
        Err(Error::Str("dechiffrer_asymmetrique_ed25519 Mauvaise taille de cle secrete, doit etre 80 bytes"))?
    }
    if cle_privee.id() != Id::ED25519 {
        Err(Error::Str("dechiffrer_asymmetrique_ed25519 Mauvais type de cle privee, doit etre ED25519"))?
    }

    let cle_peer_public_raw = &cle_chiffree[0..32];
    let cle_peer_intermediaire = PKey::public_key_from_raw_bytes(cle_peer_public_raw, Id::X25519)?;

    let cle_secrete_dechiffree = if cle_chiffree.len() == 32 {
        deriver_asymetrique_ed25519_peer(&cle_peer_intermediaire, cle_privee)?
    } else {
        // Dechiffage de la cle secrete avec ChaCha20Poly1305
        let cle_secrete_chiffree_tag = &cle_chiffree[32..80];
        // Trouver cle secrete de dechiffrage de la cle privee
        let cle_secrete_intermediaire = deriver_asymetrique_ed25519_peer(&cle_peer_intermediaire, &cle_privee)?;
        // Utiliser chacha20poly1305 pour dechiffrer la cle secrete
        let aead = ChaCha20Poly1305::new(cle_secrete_intermediaire.0[..].into());
        // Note : on utilise la cle publique du peer (valeur random) comme nonce pour le chiffrage

        let mut nonce = [0u8; 32];  // 32 bytes Blake2s
        hacher_bytes_into(&cle_peer_public_raw[..], HachageCode::Blake2s256, &mut nonce);
        let m = aead.decrypt(nonce[0..12].into(), cle_secrete_chiffree_tag.as_ref())?;
        let mut cle_secrete_dechiffree = CleSecrete([0u8; 32]);
        cle_secrete_dechiffree.0.copy_from_slice(&m[..]);

        cle_secrete_dechiffree
    };

    Ok(cle_secrete_dechiffree)
}

pub fn convertir_public_ed25519_to_x25519_openssl(public_key: &PKey<Public>) -> Result<PKey<Public>, Error> {
    let pk = public_key.raw_public_key()?;
    let cle_publique_x25519 = convertir_public_ed25519_to_x25519(&pk)?;
    Ok(PKey::public_key_from_raw_bytes(&cle_publique_x25519, Id::X25519)?)
}

pub fn convertir_public_ed25519_to_x25519(cle_publique_bytes: &[u8]) -> Result<ClePubliqueX25519, Error> {
    // Copier cle en input pour avoir buffer de taille connue
    let mut cle_public_ref = crypto_sign_ed25519::PublicKey::default();
    cle_public_ref.clone_from_slice(&cle_publique_bytes[0..32]);

    // Buffer pour cle convertie
    let mut cle_publique_x25519: crypto_sign_ed25519::PublicKey = ClePubliqueX25519::default();

    // Convertir
    crypto_sign_ed25519::crypto_sign_ed25519_pk_to_curve25519(
        &mut cle_publique_x25519,
        &cle_public_ref
    )?;

    Ok(cle_publique_x25519)
}

fn convertir_private_ed25519_to_x25519(ca_key: &PKey<Private>) -> Result<PKey<Private>, Error> {
    let cle_privee_ca = match ca_key.raw_private_key() {
        Ok(inner) => inner,
        Err(e) => Err(Error::Openssl(e))?
    };
    let mut cle_privee_ca_sk: crypto_sign_ed25519::SecretKey = [0u8; 64];
    cle_privee_ca_sk[0..32].copy_from_slice(&cle_privee_ca[..]);
    let mut cle_privee_ca_x25519 = [0u8; 32];
    crypto_sign_ed25519::crypto_sign_ed25519_sk_to_curve25519(
        &mut cle_privee_ca_x25519,
        &cle_privee_ca_sk
    );

    match PKey::private_key_from_raw_bytes(&cle_privee_ca_x25519, Id::X25519) {
        Ok(inner) => Ok(inner),
        Err(e) => Err(Error::Openssl(e))
    }
}

#[cfg(test)]
mod x25519_tests {
    use super::*;
    use log::debug;

    #[test_log::test]
    fn test_chiffrage_asymmetrique() {
        debug!("Chiffrer cle secrete");

        // Creer ensemble de cles
        let cle_ca = PKey::generate_ed25519().unwrap();
        let cle_ca_public = PKey::public_key_from_raw_bytes(&cle_ca.raw_public_key().unwrap()[..], Id::ED25519).unwrap();

        // Chiffrer cle secrete
        let derived_key = deriver_asymetrique_ed25519(&cle_ca_public).unwrap();
        debug!("Peer:\n{:?}", derived_key.public_peer);

        // Recalculer avec cle publique peer et cle privee ca
        let peer_x25519 = PKey::public_key_from_raw_bytes(&derived_key.public_peer, Id::X25519).unwrap();
        debug!("Peer x25519 lu : {:?}", peer_x25519);
        let cle_secrete_rederivee = deriver_asymetrique_ed25519_peer(&peer_x25519, &cle_ca).unwrap();

        assert_eq!(derived_key.secret.0, cle_secrete_rederivee.0);
        debug!{"Cle secretes match OK!"};
    }

    #[test_log::test]
    fn chiffrer_cle_secrete() {

        // Generer une cle publique pour chiffrer
        let cle_ed25519 = PKey::generate_ed25519().unwrap();
        let cle_ed25519_publique = PKey::public_key_from_raw_bytes(
            &cle_ed25519.raw_public_key().unwrap(), Id::ED25519).unwrap();

        // Generer une cle secrete de 32 bytes
        let cle_secrete = [4u8; 32];  // Cle secrete, val 0x04 sur 32 bytes

        let cle_chiffree = chiffrer_asymmetrique_ed25519(&cle_secrete, &cle_ed25519_publique).unwrap();
        debug!("Cle chiffree: {:?}", cle_chiffree);

        // Tenter de dechiffrer la cle secrete avec la cle privee
        let cle_dechiffree = dechiffrer_asymmetrique_ed25519(&cle_chiffree[..], &cle_ed25519).unwrap();
        debug!("Cle dechiffree: {:?}", cle_dechiffree.0);

        assert_eq!(cle_secrete, cle_dechiffree.0);
        debug!("Cle secrete dechiffree OK");
    }
}
