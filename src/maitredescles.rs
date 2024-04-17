use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use heapless::{Vec, String};
use serde::{Deserialize, Serialize};
use base64::{engine::general_purpose::STANDARD_NO_PAD as base64_nopad, Engine as _};
use multibase::Base;
use openssl::pkey::{Id, PKey, Private};
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::error::Error;
use crate::hachages::{HacheurBlake2s256, HacheurInterne};
use crate::x25519::{CleSecreteX25519, dechiffrer_asymmetrique_ed25519};

pub const VERSION_1: i32 = 1;   // Signature ed25519

pub const TAILLE_DOMAINE_STR: usize = 40;

#[derive(Debug, Clone, Serialize_repr, Deserialize_repr)]
#[repr(i32)]
pub enum SignatureDomainesVersion {
    NonSigne = 0,
    Version1 = 1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Utilitaires de messagerie et signature pour commandes maitre des cles
/// La liste des domaines est extraite en json (e.g. ["domaine1","domaine2",...]) et signee.
pub struct SignatureDomaines {
    /// Liste des domaines supportes pour la cle.
    pub domaines: Vec<String<TAILLE_DOMAINE_STR>, 4>,

    pub version: SignatureDomainesVersion,

    /// Cle dechiffrable par le CA.
    /// Utilise les formats de chiffrage reconnus pour le CA. Voir x25519::FormatCleAsymmetrique
    pub ca: Option<String<150>>,

    /// Signature des domaines en utilisant la cle secrete
    pub signature: String<96>,
}

impl SignatureDomaines {

    // pub fn new<S, T>(domaines: &std::vec::Vec<S>, ca: Option<T>, rechiffrage: String<96>) -> Result<Self, Error>
    //     where S: AsRef<str>, T: AsRef<str>
    // {
    //     if domaines.len() == 0 {
    //         Err(Error::Str("La liste des domaines est vide"))?
    //     }
    //
    //     let ca = match ca {
    //         Some(inner) => Some(inner.as_ref().try_into().map_err(|_| Error::Str("SignatureDomaines.new Erreur conversion signature ca (>128 chars)"))?),
    //         None => None
    //     };
    //
    //     let mut domaines_owned = Vec::new();
    //     for domaine in domaines {
    //         let domaine = domaine.as_ref().try_into()
    //             .map_err(|_| Error::Str("SignatureDomaines.new Erreur conversion domaine (>32 chars)"))?;
    //         domaines_owned.push(domaine)
    //             .map_err(|_| Error::Str("SignatureDomaines.new Erreur, max 4 domaines"))?;
    //     }
    //
    //     Ok(Self{
    //         domaines: domaines_owned,
    //         version: VERSION_1,
    //         peer_ca: None,
    //         signature_secrete: rechiffrage,
    //     })
    // }

    pub fn signer_ed25519<S>(domaines: &std::vec::Vec<S>, peer_public: &[u8; 32], cle_secrete: &[u8; 32])
                             -> Result<Self, Error>
        where S: AsRef<str>
    {
        if domaines.len() == 0 {
            Err(Error::Str("La liste des domaines est vide"))?
        }

        let mut domaines_vec: Vec<String<TAILLE_DOMAINE_STR>, 4> = Vec::new();
        for domaine in domaines {
            let domaine = domaine.as_ref().try_into()
                .map_err(|_| Error::Str("SignatureDomaines.signer_ed25519 Erreur domaine, max 32 chars"))?;
            domaines_vec.push(domaine)
                .map_err(|_| Error::Str("SignatureDomaines.signer_ed25519 Erreur, max 4 domaines"))?;
        }

        // Hacher les domaines avec blake2s
        let hachage_domaines = hacher_domaines(&mut domaines_vec)?;

        // Signer les domaines en utilisant la cle_secrete comme cle de signature
        let signature_secrete_string = signer_hachage(cle_secrete, hachage_domaines.as_slice())?;

        // Conserver le peer public - devient la methode pour restaurer la cle avec le CA
        let cle_publique_base64 = base64_nopad.encode(peer_public);
        let peer_ca = cle_publique_base64.as_str().try_into()
            .map_err(|_| Error::Str("SignatureDomaines.signer_ed25519 Erreur peer_ca >50 chars"))?;

        Ok(Self {
            domaines: domaines_vec,
            version: SignatureDomainesVersion::Version1,
            ca: Some(peer_ca),
            signature: signature_secrete_string,
        })
    }

    pub fn verifier_derivee<B>(&self, cle_secrete: B) -> Result<(), Error>
        where B: AsRef<[u8]>
    {
        let hachage_domaines = hacher_domaines(&self.domaines)?;

        let cle_secrete = cle_secrete.as_ref().try_into()
            .map_err(|_| Error::Str("verifier_rechiffrage Erreur conversion cle secrete, taille incorrecte"))?;
        let signing_key = SigningKey::from_bytes(cle_secrete);

        let signature_bytes: Vec<u8, 64> = decode_base64(&self.signature)?;
        let signature = Signature::from_slice(signature_bytes.as_slice())
            .map_err(|_| Error::Str("verifier_rechiffrage Erreur Signature::from_slice"))?;

        signing_key.verify(&hachage_domaines, &signature)
            .map_err(|_| Error::Str("verifier_rechiffrage Erreur signature"))
    }

    /// Retourne la valeur blake2s de la signature secrete encodee en base58btc.
    /// Cette valeur peut etre utilisee comme reference unique pour la cle.
    pub fn get_cle_ref(&self) -> Result<String<60>, Error> {
        let signature_secrete: Vec<u8, 64> = decode_base64(&self.signature)?;
        let mut hachage_signature_secrete = [0u8; 32];
        let mut hacheur = HacheurBlake2s256::new();
        hacheur.update(signature_secrete.as_slice());
        hacheur.finalize_into(&mut hachage_signature_secrete);

        let val = multibase::encode(Base::Base58Btc, hachage_signature_secrete);
        Ok(val.as_str().try_into().map_err(|_| Error::Str("Erreur conversion en String pour get_cle_ref"))?)
    }

    pub fn dechiffrer_ca(&self, cle_privee_ca: &PKey<Private>) -> Result<CleSecreteX25519, Error> {
        let cle_chiffree = match self.ca.as_ref() {
            Some(inner) => inner,
            None => Err(Error::Str("SignatureDomaines.dechiffrer_ca peer_ca est None"))?
        };
        let cle_chiffre_bytes = base64_nopad.decode(cle_chiffree)
            .map_err(|_| Error::Str("SignatureDomaines.dechiffrer_ca Erreur base64_nopad.decode de la cle chiffree"))?;
        dechiffrer_asymmetrique_ed25519(cle_chiffre_bytes.as_slice(), cle_privee_ca)
    }
}

fn hacher_domaines(domaines_vec: &Vec<String<TAILLE_DOMAINE_STR>, 4>) -> Result<[u8; 32], Error> {
    let domaines_string = serde_json::to_string(&domaines_vec)?;
    let mut hachage_domaines = [0u8; 32];
    let mut hacheur = HacheurBlake2s256::new();
    hacheur.update(domaines_string.as_bytes());
    hacheur.finalize_into(&mut hachage_domaines);
    Ok(hachage_domaines)
}

fn signer_hachage<const L: usize>(cle: &[u8; 32], hachage: &[u8]) -> Result<String<L>, Error> {
    let peer_prive_signing_key = SigningKey::from_bytes(cle);
    let signature = peer_prive_signing_key.sign(hachage);
    encode_base64(signature.to_bytes())
}

fn encode_base64<const L: usize, T>(valeur: T) -> Result<String<L>, Error>
    where T: AsRef<[u8]>
{
    // Creer un Vec comme buffer de signature
    let mut buffer_signature: Vec<u8, L> = Vec::new();
    buffer_signature.resize(L, 0)
        .map_err(|_| Error::Str("SignatureDomaines.convertir_base64 Erreur resize buffer_signature"))?;
    let taille = base64_nopad.encode_slice(valeur, buffer_signature.as_mut_slice())
        .map_err(|_| Error::Str("SignatureDomaines.convertir_base64 Erreur base64_nopad.encode_slice cle derivee"))?;

    // Ajuster la taille exacte du resultat
    buffer_signature.truncate(taille);

    Ok(String::from_utf8(buffer_signature)?)
}

fn decode_base64<const L: usize, S>(valeur: S) -> Result<Vec<u8, L>, Error>
    where S: AsRef<str>
{
    let mut output_vec: Vec<u8, L> = Vec::new();

    output_vec.resize(L, 0)
        .map_err(|_| Error::Str("SignatureDomaines.decode_base64 Erreur resize public_peer_bytes"))?;

    let taille = base64_nopad.decode_slice(valeur.as_ref().as_bytes(), &mut output_vec.as_mut_slice())
        .map_err(|_| Error::Str("SignatureDomaines.decode_base64 Erreur base64_nopad.decode_slice"))?;

    if taille != L {
        Err(Error::Str("SignatureDomaines.decode_base64 Erreur decodage, taille output incorrecte"))?
    }

    Ok(output_vec)
}

#[cfg(test)]
mod maitredescles_tests {
    use log::info;
    use crate::x25519::deriver_asymetrique_ed25519;
    use super::*;

    #[test_log::test]
    fn test_parse_message() {
        let domaines = vec!["domaine1", "domaine2"];
        let cle_peer = b"01234567890123456789012345678901".as_slice();
        let cle_dechiffree = b"12345678901234567890123456789012".as_slice();
        let signature = SignatureDomaines::signer_ed25519(
            &domaines, cle_peer.try_into().unwrap(), cle_dechiffree.try_into().unwrap()).unwrap();
        info!("Signature\n{}", serde_json::to_string_pretty(&signature).unwrap());

        assert_eq!("2XvfMHgrlOV6q1BH4IGNzi+79lWJb+/l5VCfNcuGMpmT0kpj5MtRMA5ImNAASJyosdMS8e7Mds6N6OfA7Xy1Dw", signature.signature.as_str());

        // Convertir la cle peer privee en cle publique base64. Verifier la signature.
        let peer_signing_key = SigningKey::from_bytes(cle_peer.try_into().unwrap());
        let verifying_key = peer_signing_key.verifying_key();
        let string_verifying_key: String<50> = encode_base64(verifying_key.as_bytes()).unwrap();

        // Verifier la signature avec la cle derivee (dechiffree)
        signature.verifier_derivee(cle_dechiffree).unwrap();
    }

    #[test_log::test]
    fn test_domaines_corrompus() {
        let domaines = vec!["domaine1"];
        let cle_peer = b"01234567890123456789012345678901".as_slice();
        let cle_dechiffree = b"12345678901234567890123456789012".as_slice();
        let mut signature = SignatureDomaines::signer_ed25519(
            &domaines, cle_peer.try_into().unwrap(), cle_dechiffree.try_into().unwrap()).unwrap();

        let mut domaines_corrompus = Vec::new();
        domaines_corrompus.push("domaine1".try_into().unwrap()).unwrap();
        domaines_corrompus.push("domaine2".try_into().unwrap()).unwrap();
        signature.domaines = domaines_corrompus;

        // Convertir la cle peer privee en cle publique base64. Verifier la signature.
        let peer_signing_key = SigningKey::from_bytes(cle_peer.try_into().unwrap());
        let verifying_key = peer_signing_key.verifying_key();
        let string_verifying_key: String<50> = encode_base64(verifying_key.as_bytes()).unwrap();

        // Verifier la signature avec la cle derivee (dechiffree)
        if let Err(Error::Str(message)) = signature.verifier_derivee(cle_dechiffree) {
            assert_eq!("verifier_rechiffrage Erreur signature", message);
        } else { panic!("signature doit etre invalide") }
    }

    #[test_log::test]
    fn test_cle_ref() {
        let domaines = vec!["domaine1"];
        let cle_peer = b"01234567890123456789012345678901".as_slice();
        let cle_dechiffree = b"12345678901234567890123456789013".as_slice();
        let signature = SignatureDomaines::signer_ed25519(
            &domaines, cle_peer.try_into().unwrap(), cle_dechiffree.try_into().unwrap()).unwrap();

        let cle_ref = signature.get_cle_ref().unwrap();
        assert_eq!("z6cji3TFvG1ovBUKGdEtc9dbXdogn4k4WvPdX3CLt7vPf", cle_ref.as_str());
    }

    #[test_log::test]
    fn test_dechiffrage_ca() {
        let domaines = vec!["domaine1"];

        // Simuler une cle CA. Utiliser la partie publique pour deriver un secret.
        let cle_private_ca = PKey::private_key_from_raw_bytes(b"34567890123456789012345678901234".as_slice(), Id::ED25519).unwrap();
        let cle_public_ca = PKey::public_key_from_raw_bytes(cle_private_ca.raw_public_key().unwrap().as_slice(), Id::ED25519).unwrap();

        // Creer une cle secrete derivee du CA.
        let cle_derivee = deriver_asymetrique_ed25519(&cle_public_ca).unwrap();
        let public_peer = &cle_derivee.public_peer;
        let cle_secrete = &cle_derivee.secret;

        // Signer les domaines
        let mut signature = SignatureDomaines::signer_ed25519(
            &domaines, public_peer, &cle_secrete.0).unwrap();

        // Utiliser la cle CA privee pour dechiffrer peer_ca.
        let cle_dechiffree = signature.dechiffrer_ca(&cle_private_ca).unwrap();
        let cle_secrete_slice = cle_secrete.0.as_slice();
        let cle_dechiffree_slice = &cle_dechiffree.0[..];

        assert_eq!(cle_secrete.0.as_slice(), cle_dechiffree.0.as_slice());
    }
}
