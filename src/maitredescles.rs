use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use heapless::{Vec, String};
use serde::{Deserialize, Serialize};
use base64::{engine::general_purpose::STANDARD_NO_PAD as base64_nopad, Engine as _};

use crate::error::Error;
use crate::hachages::{HacheurBlake2s256, HacheurInterne};

pub const VERSION_1: i32 = 1;   // Signature ed25519

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Utilitaires de messagerie et signature pour commandes maitre des cles
/// La liste des domaines est extraite en json (e.g. ["domaine1","domaine2",...]) et signee.
pub struct SignatureDomaines {
    /// Liste des domaines supportes pour la cle.
    pub domaines: Vec<String<32>, 4>,

    pub version: i32,

    /// Signature des domaines pour la cle CA en utilisant la cle peer privee
    /// Cette signature existe uniquement pour une cle derivee a partir du CA.
    pub ca: Option<String<96>>,

    /// Signature des domaines en utilisant la cle derivee (secrete)
    pub derivee: String<96>,
}

impl SignatureDomaines {

    pub fn new<S, T>(domaines: &std::vec::Vec<S>, ca: Option<T>, rechiffrage: String<96>) -> Result<Self, Error>
        where S: AsRef<str>, T: AsRef<str>
    {
        if domaines.len() == 0 {
            Err(Error::Str("La liste des domaines est vide"))?
        }

        let ca = match ca {
            Some(inner) => Some(inner.as_ref().try_into().map_err(|_| Error::Str("SignatureDomaines.new Erreur conversion signature ca (>128 chars)"))?),
            None => None
        };

        let mut domaines_owned = Vec::new();
        for domaine in domaines {
            let domaine = domaine.as_ref().try_into()
                .map_err(|_| Error::Str("SignatureDomaines.new Erreur conversion domaine (>32 chars)"))?;
            domaines_owned.push(domaine)
                .map_err(|_| Error::Str("SignatureDomaines.new Erreur, max 4 domaines"))?;
        }

        Ok(Self{
            domaines: domaines_owned,
            version: VERSION_1,
            ca,
            derivee: rechiffrage,
        })
    }

    pub fn signer_ed25519<S>(domaines: &std::vec::Vec<S>, peer_prive: &[u8; 32], cle_derivee: &[u8; 32])
        -> Result<Self, Error>
        where S: AsRef<str>
    {
        if domaines.len() == 0 {
            Err(Error::Str("La liste des domaines est vide"))?
        }

        let mut domaines_vec: Vec<String<32>, 4> = Vec::new();
        for domaine in domaines {
            let domaine = domaine.as_ref().try_into()
                .map_err(|_| Error::Str("SignatureDomaines.signer_ed25519 Erreur domaine, max 32 chars"))?;
            domaines_vec.push(domaine)
                .map_err(|_| Error::Str("SignatureDomaines.signer_ed25519 Erreur, max 4 domaines"))?;
        }

        // Hacher les domaines avec blake2s
        let hachage_domaines = hacher_domaines(&mut domaines_vec)?;

        // Signer les domaines en utilisant le peer_prive et cle_derivee comme cle de signature
        let signature_peer_prive_string = signer_hachage(peer_prive, hachage_domaines.as_slice())?;
        let signature_derive_string = signer_hachage(cle_derivee, hachage_domaines.as_slice())?;

        Ok(Self {
            domaines: domaines_vec,
            version: VERSION_1,
            ca: Some(signature_peer_prive_string),
            derivee: signature_derive_string,
        })
    }

    /// Verifie la signature des domaines vec la valeur publique de la cle pour CA.
    pub fn verifier_ca_base64(&self, public_peer: String<64>) -> Result<(), Error> {
        let ca = match self.ca.as_ref() {
            Some(inner) => inner,
            None => Err(Error::Str("CA est None"))?
        };

        let hachage_domaines = hacher_domaines(&self.domaines)?;

        let public_peer_bytes: Vec<u8, 32> = decode_base64(public_peer)?;
        let public_peer_slice = public_peer_bytes.as_slice().try_into()
            .map_err(|_| Error::Str("verifier_ca_base64 Erreur public_peer_bytes.as_slice, n'est pas 32 bytes"))?;
        let signature_bytes: Vec<u8, 64> = decode_base64(ca)?;
        let signature = Signature::from_slice(signature_bytes.as_slice())
            .map_err(|_| Error::Str("verifier_ca_base64 Erreur Signature::from_slice"))?;

        let verifying_key = VerifyingKey::from_bytes(public_peer_slice)
            .map_err(|_| Error::Str("verifier_ca_base64 Erreur VerifyingKey::from_bytes"))?;

        verifying_key.verify(&hachage_domaines, &signature)
            .map_err(|_| Error::Str("verifier_ca_base64 Erreur signature"))
    }

    pub fn verifier_derivee<B>(&self, cle_secrete: B) -> Result<(), Error>
        where B: AsRef<[u8]>
    {
        let hachage_domaines = hacher_domaines(&self.domaines)?;

        let cle_secrete = cle_secrete.as_ref().try_into()
            .map_err(|_| Error::Str("verifier_rechiffrage Erreur conversion cle secrete, taille incorrecte"))?;
        let signing_key = SigningKey::from_bytes(cle_secrete);

        let signature_bytes: Vec<u8, 64> = decode_base64(&self.derivee)?;
        let signature = Signature::from_slice(signature_bytes.as_slice())
            .map_err(|_| Error::Str("verifier_rechiffrage Erreur Signature::from_slice"))?;

        signing_key.verify(&hachage_domaines, &signature)
            .map_err(|_| Error::Str("verifier_rechiffrage Erreur signature"))
    }

}

fn hacher_domaines(domaines_vec: &Vec<String<32>, 4>) -> Result<[u8; 32], Error> {
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
    use super::*;

    #[test_log::test]
    fn test_parse_message() {
        let domaines = vec!["domaine1", "domaine2"];
        let cle_peer = b"01234567890123456789012345678901".as_slice();
        let cle_dechiffree = b"12345678901234567890123456789012".as_slice();
        let signature = SignatureDomaines::signer_ed25519(
            &domaines, cle_peer.try_into().unwrap(), cle_dechiffree.try_into().unwrap()).unwrap();
        info!("Signature {:?}", signature);

        assert_eq!("G/LIt+VgdhpkfkGavFgxbDDDzyHRUJPm2E7zZaxuB/mxiF15wYnq+MuTj8MjoMOk6zkauTmqfu+e9UL3i8bCAQ", signature.ca.as_ref().unwrap().as_str());
        assert_eq!("2XvfMHgrlOV6q1BH4IGNzi+79lWJb+/l5VCfNcuGMpmT0kpj5MtRMA5ImNAASJyosdMS8e7Mds6N6OfA7Xy1Dw", signature.derivee.as_str());

        // Convertir la cle peer privee en cle publique base64. Verifier la signature.
        let peer_signing_key = SigningKey::from_bytes(cle_peer.try_into().unwrap());
        let verifying_key = peer_signing_key.verifying_key();
        let string_veryfing_key = encode_base64(verifying_key.as_bytes()).unwrap();
        signature.verifier_ca_base64(string_veryfing_key).unwrap();

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
        let string_veryfing_key = encode_base64(verifying_key.as_bytes()).unwrap();

        if let Err(Error::Str(message)) = signature.verifier_ca_base64(string_veryfing_key) {
            assert_eq!("verifier_ca_base64 Erreur signature", message);
        } else { panic!("signature doit etre invalide") }

        // Verifier la signature avec la cle derivee (dechiffree)
        if let Err(Error::Str(message)) = signature.verifier_derivee(cle_dechiffree) {
            assert_eq!("verifier_rechiffrage Erreur signature", message);
        } else { panic!("signature doit etre invalide") }
    }

}
