use core::str::{from_utf8, FromStr};
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use chrono::{DateTime, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_repr::{Serialize_repr, Deserialize_repr};
use heapless::{Vec, FnvIndexMap, String};
use log::{debug, error};
use serde_json::Value;
use base64::{engine::general_purpose::STANDARD_NO_PAD as base64_nopad, Engine as _};
use serde::de::DeserializeOwned;

use crate::chiffrage_cles::{Cipher, CleChiffrageX25519, CleDechiffrageX25519Impl, Decipher};
use crate::chiffrage_mgs4::DecipherMgs4;
use crate::ed25519::{MessageId, signer_into, verifier};
use crate::error::Error;
use crate::hachages::{HacheurInterne, HacheurBlake2s256};
use crate::x25519::dechiffrer_asymmetrique_ed25519;
use crate::x509::{EnveloppeCertificat, EnveloppePrivee};

pub const CONST_NOMBRE_CERTIFICATS_MAX: usize = 4;
const CONST_NOMBRE_CLES_MAX: usize = 8;

// La taille du buffer avec no_std (microcontrolleur) est 24kb. Sinon taille max message est 10mb.
//#[cfg(not(feature = "std"))]
pub const CONST_BUFFER_MESSAGE_MIN: usize = 24 * 1024;
//#[cfg(feature = "std")]
//pub const CONST_BUFFER_MESSAGE: usize = 10 * 1024 * 1024;

pub trait MessageValidable<'a>: Sync {
    /// Cle publique (pour EC/Ed25519) ou fingerprint du certificat.
    fn pubkey(&'a self) -> &'a str;

    /// Estampille du message (timestamp)
    fn estampille(&'a self) -> &'a DateTime<Utc>;

    /// Certificat a utiliser pour valider la signature (Vec<String PEM>).
    fn certificat(&self) -> Result<Option<std::vec::Vec<std::string::String>>, Error>;

    /// Certificat de la millegrille (PEM)
    fn millegrille(&'a self) -> Option<&'a str>;

    /// Verifie que la valeur de hachage du message correspond au contenu.
    /// Lance une Err si invalide.
    /// Note : ne valide pas la correspondance au certificat/IDMG ni les dates.
    fn verifier_signature(&mut self) -> Result<(), Error>;
}

#[derive(Debug, Clone, PartialEq, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum MessageKind {
    Document = 0,
    Requete = 1,
    Commande = 2,
    Transaction = 3,
    Reponse = 4,
    Evenement = 5,
    ReponseChiffree = 6,
    TransactionMigree = 7,
    CommandeInterMillegrille = 8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DechiffrageInterMillegrille<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cles: Option<FnvIndexMap<&'a str, &'a str, CONST_NOMBRE_CLES_MAX>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cle_id: Option<&'a str>,
    pub format: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hachage: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<&'a str>,
}

impl<'a> DechiffrageInterMillegrille<'a> {
    fn to_cle_dechiffrage(&self, enveloppe_privee: &EnveloppePrivee)
        -> Result<CleDechiffrageX25519Impl, Error>
    {
        // Trouver la cle chiffree correspondant a la cle privee.
        let fingerprint = enveloppe_privee.fingerprint()?;
        let cle_chiffree = match self.cles.as_ref() {
            Some(inner) => match inner.get(fingerprint.as_str()) {
                Some(inner) => *inner,
                None => Err(Error::String(format!("into_cle_dechiffrage Cle {} absente", fingerprint)))?
            },
            None => Err(Error::Str("into_cle_dechiffrage Section dechiffrage absente"))?
        };

        // Dechiffrer la cle
        let cle_chiffree_bytes = multibase::decode(cle_chiffree)?.1;
        let cle_secrete = dechiffrer_asymmetrique_ed25519(
            cle_chiffree_bytes.as_slice(), &enveloppe_privee.cle_privee)?;

        // Le nonce/iv/header depend de l'algorithme mais il est toujours requis.
        let nonce = match self.nonce.as_ref() {
            Some(inner) => *inner,
            None => match self.header {
                Some(inner) => inner,
                None => Err(Error::Str("Nonce/header absent"))?
            }
        };

        // La verification depend de l'algorithme.
        let verification = match self.verification.as_ref() {
            Some(inner) => Some(inner.to_string()),
            None => match self.hachage.as_ref() {
                Some(inner) => Some(inner.to_string()),
                None => None
            }
        };

        Ok(CleDechiffrageX25519Impl {
            cle_chiffree: cle_chiffree.to_string(),
            cle_secrete: Some(cle_secrete),
            format: self.format.try_into()?,
            nonce: Some(nonce.to_string()),
            verification,
        })
    }
}

impl<'a> Into<DechiffrageInterMillegrilleOwned> for &DechiffrageInterMillegrille<'a> {
    fn into(self) -> DechiffrageInterMillegrilleOwned {
        let cles = match self.cles.as_ref() {
            Some(inner) => {
                let mut cles = BTreeMap::new();
                for (cle, value) in inner {
                    cles.insert(cle.to_string(), value.to_string());
                }
                Some(cles)
            },
            None => None
        };

        DechiffrageInterMillegrilleOwned {
            cle_id: match self.cle_id { Some(inner) => Some(inner.to_string()), None => None },
            cles,
            format: self.format.to_string(),
            hachage: match self.hachage { Some(inner) => Some(inner.to_string()), None => None },
            header: match self.header { Some(inner) => Some(inner.to_string()), None => None },
            nonce: match self.nonce { Some(inner) => Some(inner.to_string()), None => None },
            verification: match self.verification { Some(inner) => Some(inner.to_string()), None => None },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DechiffrageInterMillegrilleOwned {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cle_id: Option<std::string::String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cles: Option<BTreeMap<std::string::String, std::string::String>>,
    pub format: std::string::String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hachage: Option<std::string::String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<std::string::String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<std::string::String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<std::string::String>,
}

impl<'a> TryInto<DechiffrageInterMillegrille<'a>> for &'a DechiffrageInterMillegrilleOwned {

    type Error = Error;

    fn try_into(self) -> Result<DechiffrageInterMillegrille<'a>, Self::Error> {

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
            format: self.format.as_str(),
            hachage: match &self.hachage { Some(inner) => Some(inner.as_str()), None => None },
            header: match &self.header { Some(inner) => Some(inner.as_str()), None => None },
            nonce: match &self.nonce { Some(inner) => Some(inner.as_str()), None => None },
            verification: match &self.verification { Some(inner) => Some(inner.as_str()), None => None },
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutageMessage<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domaine: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partition: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<&'a str>,
}

impl<'a> RoutageMessage<'a> {
    pub fn for_action(domaine: &'a str, action: &'a str) -> Self {
        RoutageMessage {
            action: Some(action),
            domaine: Some(domaine),
            partition: None,
            user_id: None
        }
    }
}

impl<'a> Into<RoutageMessageOwned> for &RoutageMessage<'a> {
    fn into(self) -> RoutageMessageOwned {
        RoutageMessageOwned {
            action: match self.action { Some(inner) => Some(inner.to_string()), None => None },
            domaine: match self.domaine { Some(inner) => Some(inner.to_string()), None => None },
            partition: match self.partition { Some(inner) => Some(inner.to_string()), None => None },
            user_id: match self.user_id { Some(inner) => Some(inner.to_string()), None => None },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoutageMessageOwned {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<std::string::String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domaine: Option<std::string::String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partition: Option<std::string::String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<std::string::String>,
}

impl<'a> Into<RoutageMessage<'a>> for &'a RoutageMessageOwned {
    fn into(self) -> RoutageMessage<'a> {
        RoutageMessage {
            action: match self.action.as_ref() { Some(inner)=>Some(inner.as_str()), None => None },
            domaine: match self.domaine.as_ref() { Some(inner)=>Some(inner.as_str()), None => None },
            partition: match self.partition.as_ref() { Some(inner)=>Some(inner.as_str()), None => None },
            user_id: match self.user_id.as_ref() { Some(inner)=>Some(inner.as_str()), None => None },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreMigration<'a> {
    #[cfg(feature = "alloc")]
    #[serde(default, with = "optionepochseconds", skip_serializing_if = "Option::is_none")]
    pub estampille: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idmg: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<&'a str>,
}

#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreMigrationOwned {
    #[serde(default, with = "optionepochseconds", skip_serializing_if = "Option::is_none")]
    pub estampille: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<std::string::String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idmg: Option<std::string::String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<std::string::String>,
}

impl<'a> Into<PreMigrationOwned> for &'a PreMigration<'a> {
    fn into(self) -> PreMigrationOwned {
        PreMigrationOwned {
            estampille: self.estampille.clone(),
            id: match self.id { Some(inner) => Some(inner.to_string()), None => None },
            idmg: match self.idmg { Some(inner) => Some(inner.to_string()), None => None },
            pubkey: match self.pubkey { Some(inner) => Some(inner.to_string()), None => None },
        }
    }
}

impl<'a> Into<PreMigration<'a>> for &'a PreMigrationOwned {
    fn into(self) -> PreMigration<'a> {
        PreMigration {
            estampille: self.estampille.clone(),
            id: match &self.id { Some(inner) => Some(inner.as_str()), None => None },
            idmg: match &self.idmg { Some(inner) => Some(inner.as_str()), None => None },
            pubkey: match &self.pubkey { Some(inner) => Some(inner.as_str()), None => None },
        }
    }
}

pub type MessageMilleGrillesRefDefault<'a> = MessageMilleGrillesRef<'a, CONST_NOMBRE_CERTIFICATS_MAX>;

#[derive(Clone, Serialize, Deserialize)]
/// Structure d'un message MilleGrille. Tous les elements sont en reference
/// a des sources externes (e.g. buffer);
/// C: nombre maximal de certificats (recommande: 4)
pub struct MessageMilleGrillesRef<'a, const C: usize> {
    /// Identificateur unique du message. Correspond au hachage blake2s-256 en hex.
    pub id: &'a str,

    /// Cle publique du certificat utilise pour la signature
    pub pubkey: &'a str,

    /// Date de creation du message
    #[serde(with = "epochseconds")]
    pub estampille: DateTime<Utc>,

    /// Kind du message, correspond a enum MessageKind
    pub kind: MessageKind,

    /// Contenu **json escaped** du message en format json-string
    /// Noter que la deserialization est incomplete, il faut retirer les escape chars
    /// avant de faire un nouveau parsing avec serde.
    #[serde(rename="contenu")]
    pub contenu_escaped: &'a str,

    /// Information de routage de message (optionnel, depend du kind)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routage: Option<RoutageMessage<'a>>,

    /// Information de migration (e.g. ancien format, MilleGrille tierce, etc).
    #[serde(rename = "pre-migration", skip_serializing_if = "Option::is_none")]
    pub pre_migration: Option<PreMigration<'a>>,

    /// IDMG d'origine du message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origine: Option<&'a str>,

    /// Information de dechiffrage pour contenu chiffre
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dechiffrage: Option<DechiffrageInterMillegrille<'a>>,

    /// Signature ed25519 encodee en hex
    #[serde(rename = "sig")]
    pub signature: &'a str,

    /// Chaine de certificats en format PEM en format **escaped** (json).
    #[serde(rename = "certificat", skip_serializing_if = "Option::is_none")]
    pub certificat_escaped: Option<Vec<&'a str, C>>,

    /// Certificat de millegrille (root).
    #[serde(rename = "millegrille", skip_serializing_if = "Option::is_none")]
    pub millegrille: Option<&'a str>,

    // /// Attachements au message. Traite comme attachments non signes (doivent etre validable separement).
    // #[cfg(feature = "serde_json")]
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub attachements: Option<HashMap<&'a str, Value>>,

    #[serde(skip)]
    /// Apres verification, conserve : signature valide, hachage valide
    pub contenu_valide: Option<(bool, bool)>,
}

impl<'a, const C: usize> MessageMilleGrillesRef<'a, C> {

    /// Parse le contenu et retourne un buffer qui peut servir a deserializer avec serde
    pub fn contenu(&self) -> Result<MessageMilleGrilleBufferContenu, Error> {
        let contenu_string = self.contenu_string()?;
        let contenu_vec =  std::vec::Vec::from(contenu_string.as_bytes());

        Ok(MessageMilleGrilleBufferContenu { buffer: contenu_vec })
    }

    pub fn contenu_string(&self) -> Result<std::string::String, Error> {
        let contenu_string: Result<std::string::String, std::string::String> = (JsonEscapeIter { s: self.contenu_escaped.chars() }).collect();
        Ok(contenu_string?)
    }

    pub fn dechiffrer<D>(&self, enveloppe_privee: &EnveloppePrivee)
        -> Result<D, Error>
        where D: DeserializeOwned
    {
        let dechiffrage = match self.dechiffrage.as_ref() {
            Some(inner) => inner,
            None => Err(Error::Str("Aucune information de dechiffrage dans le message"))?
        };
        let cle_dechiffrage = dechiffrage.to_cle_dechiffrage(enveloppe_privee)?;
        let decipher = DecipherMgs4::new(&cle_dechiffrage)?;
        let data_chiffre = base64_nopad.decode(self.contenu_escaped)
            .map_err(|e| Error::String(format!("MessageMilleGrillesRef.dechiffrer Erreur decodage base64 du contenu : {:?}", e)))?;
        let data_dechiffre = decipher.gz_to_vec(data_chiffre.as_slice())?;
        Ok(serde_json::from_slice(data_dechiffre.as_slice())?)
        // debug!("Data dechiffre vec (len: {}):\n{:?}", data_dechiffre.len(), data_dechiffre);
        // let data_dechiffre_str = from_utf8(data_dechiffre.as_slice()).unwrap();
        // debug!("Data dechiffre str (len: {}):\n{}", data_dechiffre_str.len(), data_dechiffre_str);
    }

}

impl<'a, const C: usize> MessageValidable<'a> for MessageMilleGrillesRef<'a, C> {
    fn pubkey(&'a self) -> &'a str {
        self.pubkey
    }

    fn estampille(&'a self) -> &'a DateTime<Utc> {
        &self.estampille
    }

    fn certificat(&self) -> Result<Option<std::vec::Vec<std::string::String>>, Error> {
        match self.certificat_escaped.as_ref() {
            Some(inner) => {
                let mut certificat_string = std::vec::Vec::new();
                for c in inner {
                    let certificat: std::string::String = serde_json::from_str(format!("\"{}\"", c).as_str())?;
                    certificat_string.push(certificat);
                }
                Ok(Some(certificat_string))
            },
            None => Ok(None)
        }
    }

    fn millegrille(&'a self) -> Option<&'a str> {
        self.millegrille.clone()
    }

    fn verifier_signature(&mut self) -> Result<(), Error> {
        if let Some(inner) = self.contenu_valide {
            if inner == (true, true) {
                return Ok(())
            }
            Err(Error::Str("verifier_signature Invalide"))?
        }

        // Verifier le hachage du message
        let hacheur = HacheurMessage::from(&*self);
        let hachage_string = hacheur.hacher()?;
        if self.id != hachage_string.as_str() {
            self.contenu_valide = Some((false, false));
            error!("verifier_signature hachage invalide : id: {}, calcule: {}", self.id, hachage_string);
            Err(Error::Str("verifier_signature hachage invalide"))?
        }

        // Extraire cle publique (bytes de pubkey) pour verifier la signature
        let mut buf_pubkey = [0u8; 32];
        hex::decode_to_slice(self.pubkey, &mut buf_pubkey).unwrap();
        let verifying_key = VerifyingKey::from_bytes(&buf_pubkey).unwrap();

        // Extraire la signature (bytes de sig)
        let mut hachage_bytes = [0u8; 32] as MessageId;
        if let Err(e) = hex::decode_to_slice(self.id, &mut hachage_bytes) {
            error!("verifier_signature Erreur hex {:?}", e);
            self.contenu_valide = Some((false, true));
            Err(Error::Str("verifier_signature:E1"))?
        }

        // Verifier la signature
        if ! verifier(&verifying_key, &hachage_bytes, self.signature) {
            self.contenu_valide = Some((false, true));
            Err(Error::Str("verifier_signature signature invalide"))?
        }

        // Marquer signature valide=true, hachage valide=true
        self.contenu_valide = Some((true, true));

        Ok(())
    }
}

#[cfg(feature = "alloc")]
#[derive(Clone, Serialize, Deserialize)]
/// Structure d'un message MilleGrille. Tous les elements sont en reference
/// a des sources externes (e.g. buffer);
pub struct MessageMilleGrillesOwned {
    /// Identificateur unique du message. Correspond au hachage blake2s-256 en hex.
    pub id: std::string::String,

    /// Cle publique du certificat utilise pour la signature
    pub pubkey: std::string::String,

    /// Date de creation du message
    #[serde(with = "epochseconds")]
    pub estampille: DateTime<Utc>,

    /// Kind du message, correspond a enum MessageKind
    pub kind: MessageKind,

    /// Contenu du message en format json-string
    /// Noter que la deserialization est incomplete, il faut retirer les escape chars
    /// avant de faire un nouveau parsing avec serde.
    pub contenu: std::string::String,

    /// Information de routage de message (optionnel, depend du kind)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routage: Option<RoutageMessageOwned>,

    /// Information de migration (e.g. ancien format, MilleGrille tierce, etc).
    #[cfg(feature = "serde_json")]
    #[serde(rename = "pre-migration", skip_serializing_if = "Option::is_none")]
    pub pre_migration: Option<PreMigrationOwned>,

    /// IDMG d'origine du message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origine: Option<std::string::String>,

    /// Information de dechiffrage pour contenu chiffre
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dechiffrage: Option<DechiffrageInterMillegrilleOwned>,

    /// Signature ed25519 encodee en hex
    #[serde(rename = "sig")]
    pub signature: std::string::String,

    /// Chaine de certificats en format PEM.
    #[serde(rename = "certificat", skip_serializing_if = "Option::is_none")]
    pub certificat: Option<std::vec::Vec<std::string::String>>,

    /// Certificat de millegrille (root).
    #[serde(rename = "millegrille", skip_serializing_if = "Option::is_none")]
    pub millegrille: Option<std::string::String>,

    /// Attachements au message. Traite comme attachments non signes (doivent etre validable separement).
    #[cfg(feature = "serde_json")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachements: Option<HashMap<std::string::String, Value>>,

    #[serde(skip)]
    /// Apres verification, conserve : signature valide, hachage valide
    pub contenu_valide: Option<(bool, bool)>,
}

impl<'a, const C: usize> TryInto<MessageMilleGrillesOwned> for MessageMilleGrillesRef<'a, C> {

    type Error = Error;

    fn try_into(self) -> Result<MessageMilleGrillesOwned, Self::Error> {

        // Retirer escape chars
        // let contenu= serde_json::from_str(format!("\"{}\"", self.contenu_escaped).as_str())?;
        let contenu = self.contenu_string()?;
        let certificat = match self.certificat_escaped {
            Some(inner) => {
                let mut certificat_string = std::vec::Vec::new();
                for c in inner {
                    let certificat: std::string::String = serde_json::from_str(format!("\"{}\"", c).as_str())?;
                    certificat_string.push(certificat);
                }
                Some(certificat_string)
            },
            None => None
        };

        Ok(MessageMilleGrillesOwned {
            id: self.id.to_string(),
            pubkey: self.pubkey.to_string(),
            estampille: self.estampille.clone(),
            kind: self.kind.clone(),
            contenu,
            routage: match self.routage.as_ref() { Some(inner) => Some(inner.into()), None => None },
            pre_migration: None,
            // pre_migration: match self.pre_migration.as_ref() {
            //     Some(inner) => Some(mapref_toowned(inner)),
            //     None => None
            // },
            origine: match self.origine.as_ref() { Some(inner) => Some(inner.to_string()), None => None },
            dechiffrage: match self.dechiffrage.as_ref() { Some(inner) => Some(inner.into()), None => None },
            signature: self.signature.to_string(),
            certificat,
            millegrille: match self.millegrille.as_ref() { Some(inner) => Some(inner.to_string()), None => None },
            attachements: None,
            // attachements: match self.attachements.as_ref() {
            //     Some(inner) => Some(inner.iter().map(|(k,v)| (k.to_string(), v.clone())).collect()),
            //     None => None
            // },
            contenu_valide: self.contenu_valide.clone(),
        })
    }
}

// fn mapref_toowned(source: &HashMap<&str, Value>) -> HashMap<std::string::String, Value> {
//     let mut hashmap = HashMap::new();
//     for (key, value) in source.iter() {
//         hashmap.insert(key.to_string(), value.to_owned());
//     }
//     hashmap
// }

impl MessageMilleGrillesOwned {

    /// Parse le contenu et retourne un buffer qui peut servir a deserializer avec serde
    pub fn deserialize<'a, D>(&'a self) -> Result<D, Error>
        where D: Deserialize<'a>
    {
        Ok(serde_json::from_str(self.contenu.as_str())?)
    }

    pub fn ajouter_attachement<K,V>(&mut self, cle: K, valeur: V) -> Result<(), Error>
        where K: Into<std::string::String>, V: Serialize
    {
        let cle = cle.into();
        let valeur: Value = serde_json::to_value(valeur)?;
        match self.attachements.as_mut() {
            Some(inner) => {
                inner.insert(cle, valeur);
            },
            None => {
                let mut hashmap = HashMap::new();
                hashmap.insert(cle, valeur);
                self.attachements = Some(hashmap);
            }
        }
        Ok(())
    }

}

impl TryInto<MessageMilleGrillesBufferDefault> for MessageMilleGrillesOwned {
    type Error = Error;

    fn try_into(self) -> Result<MessageMilleGrillesBufferDefault, Self::Error> {
        (&self).try_into()
    }
}

impl TryInto<MessageMilleGrillesBufferDefault> for &MessageMilleGrillesOwned {
    type Error = Error;

    fn try_into(self) -> Result<MessageMilleGrillesBufferDefault, Self::Error> {
        let vec_message = serde_json::to_vec(self)?;
        Ok(MessageMilleGrillesBufferDefault::from(vec_message))
    }
}

impl<'a> MessageValidable<'a> for MessageMilleGrillesOwned {
    fn pubkey(&'a self) -> &'a str {
        self.pubkey.as_str()
    }

    fn estampille(&'a self) -> &'a DateTime<Utc> {
        &self.estampille
    }

    fn certificat(&self) -> Result<Option<std::vec::Vec<std::string::String>>, Error> {
        Ok(self.certificat.clone())
    }

    fn millegrille(&'a self) -> Option<&'a str> {
        match self.millegrille.as_ref() { Some(inner) => Some(inner.as_str()), None => None }
    }

    fn verifier_signature(&mut self) -> Result<(), Error> {
        if let Some(inner) = self.contenu_valide {
            if inner == (true, true) {
                return Ok(())
            }
            Err(Error::Str("verifier_signature Invalide"))?
        }

        // Verifier le hachage du message
        let hacheur = HacheurMessage::try_from(&*self)?;
        let hachage_string = hacheur.hacher()?;
        if self.id.as_str() != hachage_string.as_str() {
            self.contenu_valide = Some((false, false));
            error!("verifier_signature hachage invalide : id: {}, calcule: {}", self.id, hachage_string);
            Err(Error::Str("verifier_signature hachage invalide"))?
        }

        // Extraire cle publique (bytes de pubkey) pour verifier la signature
        let mut buf_pubkey = [0u8; 32];
        hex::decode_to_slice(&self.pubkey, &mut buf_pubkey).unwrap();
        let verifying_key = VerifyingKey::from_bytes(&buf_pubkey).unwrap();

        // Extraire la signature (bytes de sig)
        let mut hachage_bytes = [0u8; 32] as MessageId;
        if let Err(e) = hex::decode_to_slice(&self.id, &mut hachage_bytes) {
            error!("verifier_signature Erreur hex {:?}", e);
            self.contenu_valide = Some((false, true));
            Err(Error::Str("verifier_signature:E1"))?
        }

        // Verifier la signature
        if ! verifier(&verifying_key, &hachage_bytes, &self.signature) {
            self.contenu_valide = Some((false, true));
            Err(Error::Str("verifier_signature signature invalide"))?
        }

        // Marquer signature valide=true, hachage valide=true
        self.contenu_valide = Some((true, true));

        Ok(())
    }

}

pub struct MessageMilleGrilleBufferContenu {
    pub buffer: std::vec::Vec<u8>,
}

impl<'a> MessageMilleGrilleBufferContenu {

    pub fn deserialize<D>(&'a self) -> Result<D, Error>
        where D: Deserialize<'a>
    {
        Ok(serde_json::from_slice(self.buffer.as_slice())?)
    }

}

struct JsonEscapeIter<'a> {
    s: std::str::Chars<'a>,
}

impl<'a> Iterator for JsonEscapeIter<'a> {
    type Item = Result<char, std::string::String>;

    fn next(&mut self) -> Option<Self::Item> {
        self.s.next().map(|c| match c {
            '\\' => {
                match self.s.next() {
                    Some(c) => match c {
                        'n' | 'r' | 'b' | 'f' | 't' | '\\' | '/' | '"' => {
                            Ok(c)
                        },
                        'u' => todo!("unicode"),
                        _ => Err(std::string::String::from("Char escape invalide")),
                    }
                    None => Err(std::string::String::from("Char escape a la fin de la str")),
                }
            },
            c => Ok(c),
        })
    }
}

// struct JsonEscapeIterAsRead<I>
//     where
//         I: Iterator,
// {
//     iter: I,
//     cursor: Option<Cursor<I::Item>>,
// }

// impl<I> JsonEscapeIterAsRead<I>
//     where
//         I: Iterator,
// {
//     pub fn new<T>(iter: T) -> Self
//         where
//             T: IntoIterator<IntoIter = I, Item = I::Item>,
//     {
//         let mut iter = iter.into_iter();
//         let cursor = iter.next().map(Cursor::new);
//         JsonEscapeIterAsRead { iter, cursor }
//     }
// }
//
// impl<I> Read for JsonEscapeIterAsRead<I>
//     where
//         I: Iterator,
//         Cursor<I::Item>: Read,
// {
//     fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
//         while let Some(ref mut cursor) = self.cursor {
//             let read = cursor.read(buf)?;
//             if read > 0 {
//                 return Ok(read);
//             }
//             self.cursor = self.iter.next().map(Cursor::new);
//         }
//         Ok(0)
//     }
// }

impl<'a, const C: usize> MessageMilleGrillesRef<'a, C> {

    pub fn parse(buffer: &'a str) -> Result<Self, ()> {
        let message_parsed: Self = match serde_json_core::from_slice(buffer.as_bytes()) {
            Ok(inner) => inner.0,
            Err(e) => {
                error!("MessageMilleGrilleBuffer serde_json_core::from_slice {:?}", e);
                Err(())?
            }
        };

        Ok(message_parsed)
    }

    pub fn builder(kind: MessageKind, contenu: &'a str)
        -> MessageMilleGrillesBuilder<'a, C>
    {
        MessageMilleGrillesBuilder::new(kind, contenu)
    }

}

#[cfg(feature = "std")]
impl<'a, const C: usize> std::fmt::Display for MessageMilleGrillesRef<'a, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("Message:{}", self.id).as_str())
    }
}

pub struct HacheurMessage<'a> {
    pub hacheur: HacheurBlake2s256,
    pub pubkey: &'a str,
    pub estampille: &'a DateTime<Utc>,
    pub kind: MessageKind,
    pub contenu: &'a str,
    pub contenu_escaped: bool,
    pub routage: Option<RoutageMessage<'a>>,
    pub pre_migration: Option<PreMigration<'a>>,
    pub origine: Option<&'a str>,
    pub dechiffrage: Option<DechiffrageInterMillegrille<'a>>,
}

impl<'a> HacheurMessage<'a> {

    pub fn new(pubkey: &'a str, estampille: &'a DateTime<Utc>, kind: MessageKind, contenu_escaped: &'a str) -> Self {
        Self {
            hacheur: HacheurBlake2s256::new(),
            pubkey,
            estampille,
            kind,
            contenu: contenu_escaped,
            contenu_escaped: true,
            routage: None,
            pre_migration: None,
            origine: None,
            dechiffrage: None,
        }
    }

    pub fn routage(mut self, routage: &'a RoutageMessage<'a>) -> Self {
        self.routage = Some(routage.clone());
        self
    }

    pub fn origine(mut self, origine: &'a str) -> Self {
        self.origine = Some(origine);
        self
    }

    pub fn dechiffrage(mut self, dechiffrage: DechiffrageInterMillegrille<'a>) -> Self {
        self.dechiffrage = Some(dechiffrage);
        self
    }

    fn hacher_base(&mut self) {
        // Hacher le debut d'un array 'json' -> ["pubkey",estampille,kind,"contenu"

        let separateur_bytes= ",".as_bytes();
        let guillemet_bytes = "\"".as_bytes();

        self.hacheur.update("[\"".as_bytes());
        self.hacheur.update(self.pubkey.as_bytes());
        self.hacheur.update(guillemet_bytes);

        // L'estampille (epoch secs) prend 10 chars. Mettre 12 pour support futur.
        let estampille_str: String<12> = String::try_from(self.estampille.timestamp()).unwrap();
        self.hacheur.update(separateur_bytes);
        self.hacheur.update(estampille_str.as_bytes());

        let kind_int = self.kind.clone() as u8;
        let kind_str: String<3> = String::try_from(kind_int).unwrap();  // 3 chars pour kind (<100)
        self.hacheur.update(separateur_bytes);
        self.hacheur.update(kind_str.as_bytes());

        // Iterer sur les chars, effectue l'escape des characteres correctement.
        self.hacheur.update(separateur_bytes);
        self.hacheur.update(guillemet_bytes);
        self.hacher_contenu();
        self.hacheur.update(guillemet_bytes);
    }

    fn hacher_contenu(&mut self) {
        let mut buffer_char = [0u8; 4];
        for c in self.contenu.chars() {
            if ! self.contenu_escaped {
                // Escape les caracters pour json-string
                match c {
                    '"' | '\\' => {
                        // Escape backslash
                        let char2 = '\\'.encode_utf8(&mut buffer_char);
                        self.hacheur.update(char2.as_bytes());
                    }
                    _ => ()
                }
            }
            let char2 = c.encode_utf8(&mut buffer_char);
            self.hacheur.update(char2.as_bytes());
        }
    }

    fn hacher_routage(&mut self) {
        let mut buffer = [0u8; 200];
        let routage_size = serde_json_core::to_slice(self.routage.as_ref().unwrap(), &mut buffer).unwrap();
        debug!("Routage\n{}", from_utf8(&buffer[..routage_size]).unwrap());
        self.hacheur.update(&buffer[..routage_size]);
    }

    fn hacher_premigration(&mut self) {
        let mut buffer = [0u8; 500];
        let routage_size = serde_json_core::to_slice(self.pre_migration.as_ref().unwrap(), &mut buffer).unwrap();
        debug!("PreMigration\n{}", from_utf8(&buffer[..routage_size]).unwrap());
        self.hacheur.update(&buffer[..routage_size]);
    }

    fn hacher_dechiffrage(&mut self) {
        // TODO : trier les cles
        let mut buffer = [0u8; 2000];
        let dechiffrage_size = serde_json_core::to_slice(self.dechiffrage.as_ref().unwrap(), &mut buffer).unwrap();
        debug!("Dechiffrage\n{}", from_utf8(&buffer[..dechiffrage_size]).unwrap());
        self.hacheur.update(&buffer[..dechiffrage_size]);
    }

    pub fn hacher(mut self) -> Result<String<64>, Error> {
        // Effectuer le hachage de : ["pubkey", estampille, kind, "contenu"
        self.hacher_base();

        let virgule = ",".as_bytes();
        let guillemet = "\"".as_bytes();

        // Determiner elements additionnels a hacher en fonction du kind
        match self.kind {
            MessageKind::Document | MessageKind::Reponse => {
                // [pubkey, estampille, kind, contenu]
                // Deja fait, rien a ajouter.
            },
            MessageKind::Requete | MessageKind::Commande | MessageKind::Transaction | MessageKind::Evenement => {
                // [pubkey, estampille, kind, contenu, routage]

                if self.routage.is_none() {
                    error!("HacheurMessage::hacher Routage requis (None)");
                    Err(Error::Str("HacheurMessage::hacher:E1"))?
                }

                // Ajouter routage
                self.hacheur.update(virgule);
                self.hacher_routage();
            },
            MessageKind::ReponseChiffree => {
                // [pubkey, estampille, kind, contenu, routage, dechiffrage]
                if self.dechiffrage.is_none() {
                    error!("HacheurMessage::hacher Dechiffrage requis");
                    Err(Error::Str("HacheurMessage::hacher:E2"))?
                }
                self.hacheur.update(virgule);
                self.hacher_dechiffrage();
            },
            MessageKind::TransactionMigree => {
                // [pubkey, estampille, kind, contenu, routage, pre_migration]
                if self.routage.is_none() || self.pre_migration.is_none() {
                    error!("HacheurMessage::hacher Champs routage et pre-migration requis");
                    Err(Error::Str("HacheurMessage::hacher:E3"))?
                }

                // Ajouter routage,pre-migration
                self.hacheur.update(virgule);
                self.hacher_routage();
                self.hacheur.update(virgule);
                self.hacher_premigration();
            },
            MessageKind::CommandeInterMillegrille => {
                // [pubkey, estampille, kind, contenu, routage, origine, dechiffrage]
                if self.routage.is_none() || self.origine.is_none() || self.dechiffrage.is_none() {
                    error!("HacheurMessage::hacher Routage/origine/dechiffrage requis (routage: {:?}, origine: {:?}, dechiffrage: {:?})",
                        self.routage, self.origine, self.dechiffrage);
                    Err(Error::Str("HacheurMessage::hacher:E4"))?
                }
                self.hacheur.update(virgule);
                self.hacher_routage();
                self.hacheur.update(virgule);

                self.hacheur.update(guillemet);
                self.hacheur.update(self.origine.unwrap().as_bytes());
                self.hacheur.update(guillemet);
                self.hacheur.update(virgule);

                self.hacher_dechiffrage();
            },
        }

        // Fermer array de hachage
        self.hacheur.update("]".as_bytes());

        let mut hachage = [0u8; 32];
        self.hacheur.finalize_into(&mut hachage);

        let mut output_str = [0u8; 64];
        hex::encode_to_slice(hachage, &mut output_str).unwrap();
        let hachage_str = from_utf8(&output_str).unwrap();

        match String::from_str(hachage_str) {
            Ok(inner) => Ok(inner),
            Err(()) => Err(Error::Str("HacheurMessage::hacher:E5"))?
        }
    }

}

impl<'a, const C: usize> From<&'a MessageMilleGrillesRef<'a, C>> for HacheurMessage<'a> {
    fn from(value: &'a MessageMilleGrillesRef<'a, C>) -> Self {
        let contenu_escaped = match value.kind {
            MessageKind::ReponseChiffree |
            MessageKind::CommandeInterMillegrille => false,
            _ => true
        };

        HacheurMessage {
            hacheur: HacheurBlake2s256::new(),
            pubkey: value.pubkey,
            estampille: &value.estampille,
            kind: value.kind.clone(),
            contenu: value.contenu_escaped,
            contenu_escaped,
            routage: value.routage.clone(),
            pre_migration: value.pre_migration.clone(),
            origine: value.origine,
            dechiffrage: value.dechiffrage.clone(),
        }
    }
}

impl<'a> TryFrom<&'a MessageMilleGrillesOwned> for HacheurMessage<'a> {
    type Error = Error;
    fn try_from(value: &'a MessageMilleGrillesOwned) -> Result<Self, Self::Error> {
        Ok(HacheurMessage {
            hacheur: HacheurBlake2s256::new(),
            pubkey: value.pubkey.as_str(),
            estampille: &value.estampille,
            kind: value.kind.clone(),
            contenu: &value.contenu,
            contenu_escaped: false,
            routage: match value.routage.as_ref() { Some(inner) => Some(inner.into()), None => None },
            pre_migration: match value.pre_migration.as_ref() { Some(inner) => Some(inner.into()), None => None },
            origine: match value.origine.as_ref() { Some(inner) => Some(inner.as_str()), None => None },
            dechiffrage: match value.dechiffrage.as_ref() { Some(inner) => Some(inner.try_into()?), None => None },
        })
    }
}

impl<const C: usize> From<std::vec::Vec<u8>> for MessageMilleGrillesBufferAlloc<C> {
    fn from(value: std::vec::Vec<u8>) -> Self {
        Self { buffer: value }
    }
}

pub type MessageMilleGrillesBufferDefault = MessageMilleGrillesBufferAlloc<CONST_NOMBRE_CERTIFICATS_MAX>;

#[cfg(feature = "alloc")]
/// Version du buffer de MessagesMilleGrilles qui support alloc (Vec sur heap)
/// Preferer cette version si alloc est disponible.
#[derive(Clone, Debug)]
pub struct MessageMilleGrillesBufferAlloc<const C: usize> {
    /// Buffer dans la heap
    pub buffer: std::vec::Vec<u8>,
}

#[cfg(feature = "alloc")]
impl<const C: usize> MessageMilleGrillesBufferAlloc<C> {

    pub fn new() -> MessageMilleGrillesBufferAlloc<C> {
        MessageMilleGrillesBufferAlloc {
            buffer: std::vec::Vec::new(),
        }
    }

    pub fn parse<'a>(&'a self) -> Result<MessageMilleGrillesRef<'a, C>, &'static str> {
        let message_str = match from_utf8(&*self.buffer) {
            Ok(inner) => inner,
            Err(e) => {
                error!("parse Erreur from_utf8 : {:?}", e);
                Err("MessageMilleGrilles::parse:E1")?
            }
        };
        debug!("Parse message : {}", message_str);
        match MessageMilleGrillesRef::parse(message_str) {
            Ok(inner) => Ok(inner),
            Err(()) => Err("MessageMilleGrilles::parse:E2")
        }
    }

    #[cfg(feature = "serde_json")]
    pub fn parse_to_owned(&self) -> Result<MessageMilleGrillesOwned, Error> {
        let message_str = match from_utf8(&*self.buffer) {
            Ok(inner) => inner,
            Err(e) => {
                error!("parse Erreur from_utf8 : {:?}", e);
                Err(Error::Str("MessageMilleGrilles::parse:E1"))?
            }
        };
        debug!("Parse message : {}", message_str);
        Ok(serde_json::from_str(message_str)?)
    }

}

pub type MessageMilleGrillesBufferHeaplessDefault = MessageMilleGrillesBufferHeapless<CONST_BUFFER_MESSAGE_MIN, CONST_NOMBRE_CERTIFICATS_MAX>;

/// Version no_std du buffer pour MessagesMilleGriles qui est Sized.
/// Fonctionne sur la stack sans alloc.
pub struct MessageMilleGrillesBufferHeapless<const B: usize, const C: usize> {
    /// Buffer dans la stack
    pub buffer: Vec<u8, B>,
}

impl<const B: usize, const C: usize> MessageMilleGrillesBufferHeapless<B, C> {

    pub fn new() -> MessageMilleGrillesBufferHeapless<B, C> {
        MessageMilleGrillesBufferHeapless {
            buffer: Vec::new(),
        }
    }

    pub fn parse<'a>(&'a self) -> Result<MessageMilleGrillesRef<'a, C>, &'static str> {
        let message_str = match from_utf8(&*self.buffer) {
            Ok(inner) => inner,
            Err(e) => {
                error!("parse Erreur from_utf8 : {:?}", e);
                Err("MessageMilleGrilles::parse:E1")?
            }
        };
        match MessageMilleGrillesRef::parse(message_str) {
            Ok(inner) => Ok(inner),
            Err(()) => Err("MessageMilleGrilles::parse:E2")
        }
    }

}


/// Convertisseur de date i64 en epoch (secondes)
pub mod epochseconds {

    use chrono::{DateTime, Utc};
    use serde::{self, Deserialize, Serializer, Deserializer};

    pub fn serialize<S>(date: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        let s = date.timestamp();
        serializer.serialize_i64(s)
    }

    pub fn deserialize<'de, D>( deserializer: D ) -> Result<DateTime<Utc>, D::Error>
        where D: Deserializer<'de>,
    {
        let s = i64::deserialize(deserializer)?;
        let dt = DateTime::from_timestamp(s, 0).unwrap();
        Ok(dt)
    }
}

pub mod optionepochseconds {

    use chrono::{DateTime, Utc};
    use serde::{self, Deserialize, Serializer, Deserializer};

    pub fn serialize<S>(date: &Option<DateTime<Utc>>, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        match date {
            Some(inner) => {
                let s = inner.timestamp();
                serializer.serialize_i64(s)
            },
            None => {
                serializer.serialize_none()
            }
        }
    }

    pub fn deserialize<'de, D>( deserializer: D ) -> Result<Option<DateTime<Utc>>, D::Error>
        where D: Deserializer<'de>,
    {
        let s = Option::deserialize(deserializer)?;
        match s {
            Some(inner) =>  {
                let dt = DateTime::from_timestamp(inner, 0).unwrap();
                Ok(Some(dt))
            },
            None => Ok(None)
        }
        // let s = i64::deserialize(deserializer)?;
        // let dt = DateTime::from_timestamp(s, 0).unwrap();
        // Ok(dt)
    }
}

#[cfg(feature = "alloc")]
pub type MessageMilleGrillesBuilderDefault<'a> = MessageMilleGrillesBuilder<'a, CONST_NOMBRE_CERTIFICATS_MAX>;

#[cfg(feature = "alloc")]
pub struct MessageMilleGrillesBuilder<'a, const C: usize> {
    estampille: DateTime<Utc>,
    kind: MessageKind,
    contenu: Cow<'a, str>,
    routage: Option<RoutageMessage<'a>>,
    origine: Option<&'a str>,
    dechiffrage: Option<DechiffrageInterMillegrilleOwned>,
    pub certificat: Option<Vec<&'a str, C>>,
    millegrille: Option<&'a str>,
    #[cfg(feature = "alloc")]
    attachements: Option<HashMap<std::string::String, Value>>,
    signing_key: Option<Cow<'a, SigningKey>>,
    cles_chiffrage: Option<std::vec::Vec<&'a EnveloppeCertificat>>,
}

#[cfg(feature = "alloc")]
impl<'a, const C: usize> MessageMilleGrillesBuilder<'a, C> {

    pub fn new(kind: MessageKind, contenu: &'a str) -> Self {
        Self {
            estampille: Utc::now(),
            kind,
            contenu: Cow::Borrowed(contenu),
            routage: None, origine: None,
            dechiffrage: None,
            certificat: None,
            millegrille: None, attachements: None,
            signing_key: None,
            cles_chiffrage: None,
        }
    }

    pub fn from_serializable<S>(kind: MessageKind, contenu: &S)
        -> Result<Self, Error>
        where S: Serialize
    {
        let contenu = serde_json::to_string(contenu)?;

        Ok(Self {
            estampille: Utc::now(),
            kind,
            contenu: Cow::Owned(contenu),
            routage: None, origine: None,
            dechiffrage: None,
            certificat: None,
            millegrille: None, attachements: None,
            signing_key: None,
            cles_chiffrage: None,
        })
    }

    pub fn estampille(mut self, estampille: DateTime<Utc>) -> Self {
        self.estampille = estampille;
        self
    }

    pub fn routage(mut self, routage: RoutageMessage<'a>) -> Self {
        self.routage = Some(routage);
        self
    }

    pub fn certificat(mut self, certificat: Vec<&'a str, C>) -> Self {
        self.certificat = Some(certificat);
        self
    }

    pub fn signing_key(mut self, signing_key: &'a SigningKey) -> Self {
        self.signing_key = Some(Cow::Borrowed(signing_key));
        self
    }

    pub fn enveloppe_signature(mut self, enveloppe: &'a EnveloppePrivee) -> Result<Self, Error> {
        let pem_vec = &enveloppe.chaine_pem;
        let mut certificat: Vec<&str, C> = Vec::new();
        certificat.extend(pem_vec.iter().map(|s| s.as_str()));
        self.certificat = Some(certificat);

        // Conserver la signing key
        self.signing_key = Some(Cow::Owned(enveloppe.try_into()?));

        Ok(self)
    }

    pub fn origine(mut self, origine: &'a str) -> Self {
        self.origine = Some(origine);
        self
    }

    pub fn millegrille(mut self, millegrille: &'a str) -> Self {
        self.millegrille = Some(millegrille);
        self
    }

    pub fn cles_chiffrage(mut self, cles_chiffrage: std::vec::Vec<&'a EnveloppeCertificat>) -> Self {
        self.cles_chiffrage = Some(cles_chiffrage);
        self
    }

    #[cfg(feature = "serde_json")]
    pub fn ajouter_attachement(mut self, key: std::string::String, value: Value) -> Self {
        match self.attachements.as_mut() {
            Some(inner) => {
                inner.insert(key, value);
                self
            },
            None => {
                let mut hashmap = HashMap::new();
                hashmap.insert(key, value);
                self.attachements = Some(hashmap);
                self
            }
        }
    }

    /// Version std avec un Vec qui supporte alloc. Permet de traiter des messages de grande taille.
    #[cfg(feature = "alloc")]
    pub fn build_into_alloc(self, buffer: &mut std::vec::Vec<u8>) -> Result<MessageMilleGrillesRef<C>, Error> {
        let signing_key = match &self.signing_key {
            Some(inner) => inner,
            None => Err(Error::Str("Signing key manquante"))?
        };

        // Calculer pubkey
        let verifying_key = signing_key.verifying_key();
        let pubkey_bytes = verifying_key.as_bytes();
        let mut buf_pubkey_str = [0u8; 64];
        hex::encode_to_slice(pubkey_bytes, &mut buf_pubkey_str).unwrap();
        let pubkey_str = from_utf8(&buf_pubkey_str).unwrap();

        let message_id = self.generer_id(pubkey_str)?;
        let signature = self.signer(message_id.as_str())?;

        let dechiffrage: Option<DechiffrageInterMillegrille<'_>> = match self.dechiffrage.as_ref() {
            Some(inner) => {
                Some(inner.try_into()?)
            },
            None => None
        };

        // let attachements = match self.attachements.as_ref() {
        //     Some(inner) => {
        //         let a = inner.iter()
        //             .map(|(k,v)| (k.as_str(), v.clone()))
        //             .collect();
        //         Some(a)
        //     },
        //     None => None
        // };

        let message_ref: MessageMilleGrillesRef<C> = MessageMilleGrillesRef {
            id: message_id.as_str(),
            pubkey: pubkey_str,
            estampille: self.estampille,
            kind: self.kind,
            contenu_escaped: self.contenu.as_ref(),
            routage: self.routage,
            // #[cfg(feature = "serde_json")]
            // pre_migration: None,
            pre_migration: None,
            origine: self.origine,
            dechiffrage,
            signature: signature.as_str(),
            certificat_escaped: self.certificat,
            millegrille: self.millegrille,
            // #[cfg(feature = "serde_json")]
            // attachements,
            contenu_valide: None,
        };

        // Ecrire dans buffer
        let message_vec = match serde_json::to_vec(&message_ref) {
            Ok(resultat) => resultat,
            Err(e) => {
                error!("build_into Erreur serde_json::to_string {:?}", e);
                Err(Error::Str("build_into:E1"))?
            }
        };
        debug!("Message serialise\n{:?}", from_utf8(message_vec.as_slice()));

        // Copier string vers vec
        buffer.clear();
        buffer.extend(message_vec);

        // Parse une nouvelle reference a partir du nouveau buffer
        // Permet de transferer l'ownership des references vers l'objet buffer
        let message_ref = MessageMilleGrillesRef::parse(from_utf8(buffer.as_slice()).unwrap()).unwrap();

        Ok(message_ref)
    }

    #[cfg(feature = "alloc")]
    pub fn encrypt_into_alloc<P, const K: usize>(mut self, buffer: &mut std::vec::Vec<u8>, cipher: P)
        -> Result<MessageMilleGrillesRef<C>, Error>
        where P: Cipher<K>
    {
        // Prendre le contenu du builder, le compresser et le chiffrer.
        let mut resultat_chiffrage = cipher.to_gz_vec(self.contenu.as_bytes())?;
        if let Some(cles_chiffrage) = self.cles_chiffrage.as_ref() {
            resultat_chiffrage.cles.chiffrer_x25519(cles_chiffrage.to_owned())?;
        }

        let contenu_base64 = base64_nopad.encode(resultat_chiffrage.ciphertext);
        self.contenu = Cow::Owned(contenu_base64);

        let cles: BTreeMap<std::string::String, std::string::String> = resultat_chiffrage.cles.cles_chiffrees
            .into_iter()
            .map(|v| (v.fingerprint, v.cle_chiffree))
            .collect();

        let format_str: &str = resultat_chiffrage.cles.format.into();

        let dechiffrage = DechiffrageInterMillegrilleOwned {
            cle_id: Some(resultat_chiffrage.hachage_bytes.clone()),
            cles: Some(cles),
            format: format_str.to_string(),
            hachage: Some(resultat_chiffrage.hachage_bytes),
            header: resultat_chiffrage.cles.nonce.clone(),
            nonce: resultat_chiffrage.cles.nonce,
            verification: resultat_chiffrage.cles.verification,
        };
        self.dechiffrage = Some(dechiffrage);

        Ok(self.build_into_alloc(buffer)?)
    }

    pub fn build_into<const B: usize>(self, buffer: &'a mut Vec<u8, B>)
                                      -> Result<MessageMilleGrillesRef<'a, C>, Error>
    {
        let signing_key = match &self.signing_key {
            Some(inner) => inner,
            None => Err(Error::Str("Signing key manquante"))?
        };

        // Calculer pubkey
        let verifying_key = signing_key.verifying_key();
        let pubkey_bytes = verifying_key.as_bytes();
        let mut buf_pubkey_str = [0u8; 64];
        hex::encode_to_slice(pubkey_bytes, &mut buf_pubkey_str).unwrap();
        let pubkey_str = from_utf8(&buf_pubkey_str).unwrap();

        let message_id = self.generer_id(pubkey_str)?;
        let signature = self.signer(message_id.as_str())?;

        // let attachements = match self.attachements.as_ref() {
        //     Some(inner) => {
        //         let a = inner.iter()
        //             .map(|(k,v)| (k.as_str(), v.clone()))
        //             .collect();
        //         Some(a)
        //     },
        //     None => None
        // };

        let message_ref: MessageMilleGrillesRef<C> = MessageMilleGrillesRef {
            id: message_id.as_str(),
            pubkey: pubkey_str,
            estampille: self.estampille,
            kind: self.kind,
            contenu_escaped: self.contenu.as_ref(),
            routage: self.routage,
            // #[cfg(feature = "serde_json")]
            // pre_migration: None,
            pre_migration: None,
            origine: self.origine,
            dechiffrage: None,  // self.dechiffrage,
            signature: signature.as_str(),
            certificat_escaped: self.certificat,
            millegrille: self.millegrille,
            // #[cfg(feature = "serde_json")]
            // attachements,
            contenu_valide: None,
        };

        // Ecrire dans buffer
        buffer.resize_default(buffer.capacity()).unwrap();
        let taille = match serde_json_core::to_slice(&message_ref, buffer) {
            Ok(taille) => taille,
            Err(e) => {
                error!("build_into Erreur serde_json_core::to_slice {:?}", e);
                Err(Error::Str("build_into:E1"))?
            }
        };
        buffer.truncate(taille);  // S'assurer que le Vec a la taille utilisee
        debug!("Message serialise\n{:?}", from_utf8(buffer).unwrap());

        // Parse une nouvelle reference a partir du nouveau buffer
        // Permet de transferer l'ownership des references vers l'objet buffer
        Ok(MessageMilleGrillesRef::parse(from_utf8(buffer).unwrap()).unwrap())
    }

    #[cfg(feature = "alloc")]
    fn generer_id(&self, pubkey: &str) -> Result<String<64>, Error> {
        // Escape chars dans le contenu. Le contenu du json-string doit avoir tous
        // les chars escaped. serde_json::to_string va s'en occuper durant la serialisation du
        // contenu.
        let contenu_escaped = match serde_json::to_string(self.contenu.as_ref()) {
            Ok(inner) => inner,
            Err(_) => Err(Error::Str("generer_id Erreur parse contenu"))?
        };
        // Retirer les guillemets au debut et la fin de la string serialisee.
        let contenu_escape_inner = &contenu_escaped[1..contenu_escaped.len()-1];
        // debug!("Contenu escaped\n{}", contenu_escaped);

        let mut hacheur = HacheurMessage::new(pubkey, &self.estampille, self.kind.clone(), contenu_escape_inner);
        if let Some(routage) = self.routage.as_ref() {
            hacheur = hacheur.routage(routage);
        }
        if let Some(origine) = self.origine {
            hacheur = hacheur.origine(origine);
        }
        if let Some(dechiffrage) = &self.dechiffrage {
            hacheur = hacheur.dechiffrage(dechiffrage.try_into()?);
        }

        hacheur.hacher()
    }

    fn signer(&self, id: &str) -> Result<String<128>, Error> {
        // Convertir id en bytes
        let mut id_bytes = [0u8; 32] as MessageId;
        if let Err(e) = hex::decode_to_slice(id, &mut id_bytes) {
            error!("Hex error sur id {} : {:?}", id, e);
            Err(Error::Str("signer:E1"))?
        }

        let signing_key = match &self.signing_key {
            Some(inner) => inner,
            None => Err(Error::Str("signer Signing key manquante"))?
        };

        let mut signature_buffer = [0u8; 128];
        let signature_str = signer_into(signing_key, &id_bytes, &mut signature_buffer);

        match String::from_str(signature_str) {
            Ok(inner) => Ok(inner),
            Err(()) => Err(Error::Str("signer:E2"))?
        }
    }
}

#[cfg(test)]
mod messages_structs_tests {
    use super::*;
    use std::path::PathBuf;
    use log::info;
    use serde_json::json;
    use crate::chiffrage_mgs4::CipherMgs4;

    const MESSAGE_1: &str = r#"{
      "id": "d49a375c980f1e70cdea697664610d70048899d1428909fdc29bd29cfc9dd1ca",
      "pubkey": "d1d9c2146de0e59971249489d971478050d55bc913ddeeba0bf3c60dd5b2cd31",
      "estampille": 1710338722,
      "kind": 5,
      "contenu": "{\"domaine\":\"CoreMaitreDesComptes\",\"exchanges_routing\":null,\"instance_id\":\"f861aafd-5297-406f-8617-f7b8809dd448\",\"primaire\":true,\"reclame_fuuids\":false,\"sous_domaines\":null}",
      "routage": {
        "action": "presenceDomaine",
        "domaine": "CoreMaitreDesComptes"
      },
      "sig": "9ff0c6443c9214ab9e8ee2d26b3ba6453e7f4f5f59477343e1b0cd747535005b13d453922faad1388e65850a1970662a69879b1b340767fb9f4bda6202412204",
      "certificat": [
        "-----BEGIN CERTIFICATE-----\nMIIClDCCAkagAwIBAgIUQuFP9EOrsQuFkWnXEH8UQNZ1EN4wBQYDK2VwMHIxLTAr\nBgNVBAMTJGY4NjFhYWZkLTUyOTctNDA2Zi04NjE3LWY3Yjg4MDlkZDQ0ODFBMD8G\nA1UEChM4emVZbmNScUVxWjZlVEVtVVo4d2hKRnVIRzc5NmVTdkNUV0U0TTQzMml6\nWHJwMjJiQXR3R203SmYwHhcNMjQwMjIwMTE0NjUzWhcNMjQwMzIyMTE0NzEzWjCB\ngTEtMCsGA1UEAwwkZjg2MWFhZmQtNTI5Ny00MDZmLTg2MTctZjdiODgwOWRkNDQ4\nMQ0wCwYDVQQLDARjb3JlMUEwPwYDVQQKDDh6ZVluY1JxRXFaNmVURW1VWjh3aEpG\ndUhHNzk2ZVN2Q1RXRTRNNDMyaXpYcnAyMmJBdHdHbTdKZjAqMAUGAytlcAMhANHZ\nwhRt4OWZcSSUidlxR4BQ1VvJE93uugvzxg3Vss0xo4HdMIHaMCsGBCoDBAAEIzQu\nc2VjdXJlLDMucHJvdGVnZSwyLnByaXZlLDEucHVibGljMAwGBCoDBAEEBGNvcmUw\nTAYEKgMEAgREQ29yZUJhY2t1cCxDb3JlQ2F0YWxvZ3VlcyxDb3JlTWFpdHJlRGVz\nQ29tcHRlcyxDb3JlUGtpLENvcmVUb3BvbG9naWUwDwYDVR0RBAgwBoIEY29yZTAf\nBgNVHSMEGDAWgBRQUbOqbsQcXmnk3+moqmk1PXOGKjAdBgNVHQ4EFgQU4+j+8rBR\nK+WeiFzo6EIR+t0C7o8wBQYDK2VwA0EAab2vFykbUk1cWugRd10rGiTKp/PKZdG5\nX+Y+lrHe8AHcrpGGtUV8mwwcDsRbw2wtRq2ENceNlQAcwblEkxLvCA==\n-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\nMIIBozCCAVWgAwIBAgIKAnY5ZhNJUlVzaTAFBgMrZXAwFjEUMBIGA1UEAxMLTWls\nbGVHcmlsbGUwHhcNMjQwMTMwMTM1NDU3WhcNMjUwODEwMTM1NDU3WjByMS0wKwYD\nVQQDEyRmODYxYWFmZC01Mjk3LTQwNmYtODYxNy1mN2I4ODA5ZGQ0NDgxQTA/BgNV\nBAoTOHplWW5jUnFFcVo2ZVRFbVVaOHdoSkZ1SEc3OTZlU3ZDVFdFNE00MzJpelhy\ncDIyYkF0d0dtN0pmMCowBQYDK2VwAyEAPUMU7tlz3HCEB+VzG8NVFQ/nFKjIOZmV\negt+ub3/7SajYzBhMBIGA1UdEwEB/wQIMAYBAf8CAQAwCwYDVR0PBAQDAgEGMB0G\nA1UdDgQWBBRQUbOqbsQcXmnk3+moqmk1PXOGKjAfBgNVHSMEGDAWgBTTiP/MFw4D\nDwXqQ/J2LLYPRUkkETAFBgMrZXADQQB6S4tids+r9e5d+mwpdkrAE2k3+8H0x65z\nWD5eP7A2XeEr0LbxRPNyaO+Q8fvnjjCKasn97MTPSCXnU/4JbWYK\n-----END CERTIFICATE-----\n"
      ],
      "attachements": {
        "exemple": {"tada": "toto"},
        "exemple2": "une string"
      }
    }"#;

    const MESSAGE_2: &str = r#"{
      "pubkey": "c77a68af482e6b93eb9214acff8ba8fe120e9907fc4f71833f0e0e44f28633f7",
      "estampille": 1710873229,
      "kind": 1,
      "contenu": "{}",
      "routage": {
        "action": "getConsignationFichiers",
        "domaine": "CoreTopologie"
      },
      "id": "56436984ac971a3b08013f2f24da832d345d75c446cef09db1384905cba671ba",
      "sig": "1afa459ca94bc47a218fa5543c5648d8fd42fbec354177adff510919fec94ed25b2ed58a35125b146f631397f257a312de5113c1cb9e5153ddff28f4b722eb02",
      "certificat": [
        "-----BEGIN CERTIFICATE-----\nMIICNTCCAeegAwIBAgIUDjXBdYYRZKopGYoEytpfIHPl0J0wBQYDK2VwMHIxLTAr\nBgNVBAMTJDU5ZWZkZDY4LTI1MWEtNGFiYS1hZTJlLWQwY2ZlMjM0M2YzNzFBMD8G\nA1UEChM4emVZbmNScUVxWjZlVEVtVVo4d2hKRnVIRzc5NmVTdkNUV0U0TTQzMml6\nWHJwMjJiQXR3R203SmYwHhcNMjQwMzE2MjIwMzA4WhcNMjQwNDE2MjIwMzI4WjCB\ngjEtMCsGA1UEAwwkNTllZmRkNjgtMjUxYS00YWJhLWFlMmUtZDBjZmUyMzQzZjM3\nMQ4wDAYDVQQLDAVtZWRpYTFBMD8GA1UECgw4emVZbmNScUVxWjZlVEVtVVo4d2hK\nRnVIRzc5NmVTdkNUV0U0TTQzMml6WHJwMjJiQXR3R203SmYwKjAFBgMrZXADIQDH\nemivSC5rk+uSFKz/i6j+Eg6ZB/xPcYM/Dg5E8oYz96N+MHwwKwYEKgMEAAQjNC5z\nZWN1cmUsMy5wcm90ZWdlLDIucHJpdmUsMS5wdWJsaWMwDQYEKgMEAQQFbWVkaWEw\nHwYDVR0jBBgwFoAUBi9eRwN/mAOj1iQmIW+U5NRb7NcwHQYDVR0OBBYEFMvYSbbV\ngmfeFwBv0snnKYq2R84AMAUGAytlcANBABYVN+crAcKhmQK1Bhi3GsyfWB8cxBvo\nj7jPDtTlZ7odEq6EJHNjewVIDzF5fxhAFEuJr6ToB5qJcKSh+asT6g4=\n-----END CERTIFICATE-----",
        "-----BEGIN CERTIFICATE-----\r\nMIIBozCCAVWgAwIBAgIKEwJHiRE3l0cjmDAFBgMrZXAwFjEUMBIGA1UEAxMLTWls\r\nbGVHcmlsbGUwHhcNMjQwMzE2MjE1NzI4WhcNMjUwOTI1MjE1NzI4WjByMS0wKwYD\r\nVQQDEyQ1OWVmZGQ2OC0yNTFhLTRhYmEtYWUyZS1kMGNmZTIzNDNmMzcxQTA/BgNV\r\nBAoTOHplWW5jUnFFcVo2ZVRFbVVaOHdoSkZ1SEc3OTZlU3ZDVFdFNE00MzJpelhy\r\ncDIyYkF0d0dtN0pmMCowBQYDK2VwAyEAI2iQQOBhz2fzhxHgFAU2MJpB7llfsDwu\r\nvGIybrbbqGCjYzBhMBIGA1UdEwEB/wQIMAYBAf8CAQAwCwYDVR0PBAQDAgEGMB0G\r\nA1UdDgQWBBQGL15HA3+YA6PWJCYhb5Tk1Fvs1zAfBgNVHSMEGDAWgBTTiP/MFw4D\r\nDwXqQ/J2LLYPRUkkETAFBgMrZXADQQD3Fh4DqpbZldMW3RUXfl5akQ0597g31ZW2\r\nnBFfY+4Xmwn1AJBJ41LPpV8shhqp7LCfdMZp4SC1+QkgLYQRXJUF\n-----END CERTIFICATE-----"
      ]
    }"#;

    const MESSAGE_3: &str = r#"{
      "id": "b92f2f8faf21e9729e6ee7670da1a2ac188b3bdb35ad6e30c4d6496da50693a6",
      "pubkey": "ce7e6ba15e3934ae304422d01759ad8f63adb163b7e468d0ce9e0834cab466b3",
      "estampille": 1682726249,
      "kind": 7,
      "contenu": "{\"csr\":\"-----BEGIN CERTIFICATE REQUEST-----\\r\\nMIGWMEoCAQAwFzEVMBMGA1UEAxMMcHJvcHJpZXRhaXJlMCowBQYDK2VwAyEAL1CU\\r\\nDsQhkqa5CkMZpEjawwGyfrwLZudnws81MRvYalOgADAFBgMrZXADQQBCsI0pw/1A\\r\\nKeDDrVLtZ3PExND0BYSLgNzKE2aLea0Np2p7wP8FaGzOKA44QY/Er5U7uiNfS3h+\\r\\nfNHwhLx1N5YL\\r\\n-----END CERTIFICATE REQUEST-----\\r\\n\",\"fingerprint_pk\":\"mL1CUDsQhkqa5CkMZpEjawwGyfrwLZudnws81MRvYalM\",\"nomUsager\":\"proprietaire\",\"securite\":\"1.public\",\"userId\":\"z2i3XjxAmArxvzMUMCNsvpHf82QY7m2mSBUBM78hZHCqMgDTNQw\"}",
      "routage": {
        "action": "inscrireUsager",
        "domaine": "CoreMaitreDesComptes"
      },
      "pre-migration": {
        "estampille": 1663106698,
        "pubkey": "7a5b4e80a506ceff47543dd2b8ce795e52865c21d555228b932fcb46d4859b8b",
        "id": "23f60b48-c1b6-4f8f-b702-52673ca8fade"
      },
      "sig": "fb62349a0a055c96d2f23dc79a8fea45afb7e6212387dd65517f000201f5550768591a6459f6355fb07f273e294b3b352f9b3cce927cc14891316f87ff2bb406",
      "attachements": {
        "evenements": {
          "_estampille": {
            "$date": {
              "$numberLong": "1663106698000"
            }
          },
          "backup_flag": false,
          "document_persiste": {
            "$date": {
              "$numberLong": "1663106698358"
            }
          },
          "signature_verifiee": {
            "$date": {
              "$numberLong": "1663106698358"
            }
          },
          "transaction_complete": true,
          "transaction_traitee": {
            "$date": {
              "$numberLong": "1663106698403"
            }
          }
        }
      }
    }"#;

    const MESSAGE_4: &str = r#"{
      "pubkey": "c0315366b8e81e8342b56a36fbef22dd9cc30c18ee9581b5b998aa39a25c7895",
      "estampille": 1712789455,
      "kind": 8,
      "contenu": "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",
      "routage": {
        "action": "rechiffrerBatch",
        "domaine": "MaitreDesCles"
      },
      "origine": "zaSDqKqrvhrGJS6oC2Zo4TtFXAc5FsbsZkcf9ADPx3u1jFepxikpxxjW",
      "dechiffrage": {
        "header": "mMb3imO7mE9+z11J7iPkIzgHYtZ/YiiUx",
        "format": "mgs4",
        "cles": {
          "609da7e7da2ecbb5c657b0030652942b4948c917de8d00b3368388cfea7527f0": "mD18R6L0X3WEOOVV1xatQj2VXqdp+Jz2eATCFtWKES0kCjeikZogRmQkBaa057H5Jy4ihVxXrIyuW5LaMJ8/oEnHhkt80K4JltU4VQqT9lQ0"
        }
      },
      "id": "97ee4c18180075c2a24b0b5bdc5c16b94dc5cfdd3811a92a672e97c7a0f46afb",
      "sig": "245d9cc9f4eac1f9790b4846f663767f24e6e6c3c87a63ff2c1fe9b8b7cf50a26cd1f873955648a564b297a5c9398f46e312d2e42d869e0b42c16cc2f437630e",
      "certificat": [
        "-----BEGIN CERTIFICATE-----\nMIICUTCCAgOgAwIBAgIUYCLS6YrnLLcbFT/WyZTzFa4JnlwwBQYDK2VwMHIxLTAr\nBgNVBAMTJGQzNDkzNDI4LTIwZGQtNDAzOS05MjJmLTA3ZDFjZTk0OTZjZTFBMD8G\nA1UEChM4emFTRHFLcXJ2aHJHSlM2b0MyWm80VHRGWEFjNUZzYnNaa2NmOUFEUHgz\ndTFqRmVweGlrcHh4alcwHhcNMjQwNDEwMjE1OTA1WhcNMjQwNTExMjE1OTI1WjBr\nMRUwEwYDVQQDDAxwcm9wcmlldGFpcmUxDzANBgNVBAsMBnVzYWdlcjFBMD8GA1UE\nCgw4emFTRHFLcXJ2aHJHSlM2b0MyWm80VHRGWEFjNUZzYnNaa2NmOUFEUHgzdTFq\nRmVweGlrcHh4alcwKjAFBgMrZXADIQDAMVNmuOgeg0K1ajb77yLdnMMMGO6VgbW5\nmKo5olx4laOBsTCBrjAZBgQqAwQBBBF1c2FnZXIsbmF2aWdhdGV1cjA7BgQqAwQD\nBDN6MmkzWGp4OEN4VWdOSExWNWduRkJOVDZqSDlMNnJ0MVM1aTZ3UGJWd0ptREVH\nSkpNeVgwFAYEKgMEBAQMcHJvcHJpZXRhaXJlMB8GA1UdIwQYMBaAFIpY8+yVYMpO\nAtBPt3hH2r1XBZ+6MB0GA1UdDgQWBBSphit5DY0gMalMoSsXalVU/RrJ+TAFBgMr\nZXADQQBmfyycOdoiRnEuPRgLSFen9TgUvZQQ9X2as64beAb1+JCaR6LL0jIRj/Nj\nYPfytpXmAVz3AIl2FkorgqijSBcC\n-----END CERTIFICATE-----",
        "-----BEGIN CERTIFICATE-----\r\nMIIBozCCAVWgAwIBAgIKE0ZAiGmIEHWCmTAFBgMrZXAwFjEUMBIGA1UEAxMLTWls\r\nbGVHcmlsbGUwHhcNMjQwNDEwMTk0NjU5WhcNMjUxMDIwMTk0NjU5WjByMS0wKwYD\r\nVQQDEyRkMzQ5MzQyOC0yMGRkLTQwMzktOTIyZi0wN2QxY2U5NDk2Y2UxQTA/BgNV\r\nBAoTOHphU0RxS3FydmhyR0pTNm9DMlpvNFR0RlhBYzVGc2JzWmtjZjlBRFB4M3Ux\r\nakZlcHhpa3B4eGpXMCowBQYDK2VwAyEADVz481/Ll2L948rgwWq+moC9Vvr8Bdxm\r\n6Wyvr4N/tUqjYzBhMBIGA1UdEwEB/wQIMAYBAf8CAQAwCwYDVR0PBAQDAgEGMB0G\r\nA1UdDgQWBBSKWPPslWDKTgLQT7d4R9q9VwWfujAfBgNVHSMEGDAWgBRm9hquaAqo\r\nOnfGRpwmrgOYtk7fzjAFBgMrZXADQQCEpBKOBd+nBPBoDmcXzI/CCg6oAQvis96n\r\n1D5wKJbMZncvgweRkE38lSKA37nOObVaYx3GXG2kT8+1UdBjCk0G\n-----END CERTIFICATE-----"
      ]
    }
    "#;

    const TEST_STRING_UTF8_1: &str = r#"
    Une chaine UTF-8 complexe \"avec chars speciaux\", \n
    et plein de surprises.\r\n
    Ḽơᶉëᶆ ȋṕšᶙṁ ḍỡḽǭᵳ ʂǐť ӓṁệẗ, ĉṓɲṩḙċťᶒțûɾ ấɖḯƥĭṩčįɳġ ḝłįʈ, șếᶑ ᶁⱺ ẽḭŭŝḿꝋď ṫĕᶆᶈṓɍ ỉñḉīḑȋᵭṵńť ṷŧ ḹẩḇőꝛế éȶ đꝍꞎôꝛȇ ᵯáꞡᶇā ąⱡîɋṹẵ.\n
    𐒈𐒝𐒑𐒛𐒐𐒘𐒕𐒖\n
    🌅🌊🌙🌶🍁🎃"#;

    #[test_log::test]
    fn test_parse_message() {
        let message_parsed = MessageMilleGrillesRefDefault::parse(MESSAGE_1).unwrap();
        info!("test_parse_message\nid: {}\nestampille: {}", message_parsed.id, message_parsed.estampille);
        assert_eq!("d49a375c980f1e70cdea697664610d70048899d1428909fdc29bd29cfc9dd1ca", message_parsed.id);
        assert_eq!("9ff0c6443c9214ab9e8ee2d26b3ba6453e7f4f5f59477343e1b0cd747535005b13d453922faad1388e65850a1970662a69879b1b340767fb9f4bda6202412204", message_parsed.signature);
        assert_eq!(MessageKind::Evenement, message_parsed.kind);
    }

    #[test_log::test]
    fn test_hacher_document() {
        let pubkey = "d1d9c2146de0e59971249489d971478050d55bc913ddeeba0bf3c60dd5b2cd31";
        let estampille = DateTime::from_timestamp(1710338722, 0).unwrap();
        // let contenu = "{\"domaine\":\"CoreMaitreDesComptes\",\"exchanges_routing\":null,\"instance_id\":\"f861aafd-5297-406f-8617-f7b8809dd448\",\"primaire\":true,\"reclame_fuuids\":false,\"sous_domaines\":null}";
        let contenu_doc = json!({"domaine": "CoreMaitreDesComptes"});
        let contenu = serde_json::to_string(&contenu_doc).unwrap();
        let contenu = serde_json::to_string(&contenu).unwrap();
        // Escape to string
        debug!("Contenu doc json:\n{}", contenu);
        let hacheur = HacheurMessage::new(pubkey, &estampille, MessageKind::Reponse, contenu.as_str());
        let resultat = hacheur.hacher().unwrap();
        assert_eq!("ed0f9fe63ffb52c470b187d309010efc1e88ff9bac755a1f3eaab7da0eaa18f8", resultat);
    }

    #[test_log::test]
    fn test_hacher_evenement() {
        let message_parsed = MessageMilleGrillesRefDefault::parse(MESSAGE_1).unwrap();
        let hacheur = HacheurMessage::from(&message_parsed);
        let resultat = hacheur.hacher().unwrap();

        // Comparer id au hachage - doit correspondre
        assert_eq!(message_parsed.id, resultat);
    }

    #[test_log::test]
    fn test_hacher_premigration() {
        let message_parsed = MessageMilleGrillesRefDefault::parse(MESSAGE_3).unwrap();
        let hacheur = HacheurMessage::from(&message_parsed);
        let resultat = hacheur.hacher().unwrap();

        // Comparer id au hachage - doit correspondre
        assert_eq!(message_parsed.id, resultat);
    }

    #[test_log::test]
    fn test_hacher_intermillegrille() {
        let message_parsed = MessageMilleGrillesRefDefault::parse(MESSAGE_4).unwrap();
        let hacheur = HacheurMessage::from(&message_parsed);
        let resultat = hacheur.hacher().unwrap();

        // Comparer id au hachage - doit correspondre
        assert_eq!(message_parsed.id, resultat);
    }

    #[test_log::test]
    fn test_verifier_signature() {
        let mut message_parsed = MessageMilleGrillesRefDefault::parse(MESSAGE_1).unwrap();
        assert!(message_parsed.verifier_signature().is_ok());
        assert_eq!(Some((true, true)), message_parsed.contenu_valide);
    }

    #[test_log::test]
    fn test_buffer_heapless() {
        let mut buffer: MessageMilleGrillesBufferHeapless<CONST_BUFFER_MESSAGE_MIN, CONST_NOMBRE_CERTIFICATS_MAX> = MessageMilleGrillesBufferHeapless::new();
        buffer.buffer.extend_from_slice(MESSAGE_1.as_bytes()).unwrap();
        let mut parsed = buffer.parse().unwrap();
        parsed.verifier_signature().unwrap();
        debug!("Parsed id: {}", parsed.id);
    }

    #[cfg(feature = "optional-defaults")]
    #[test_log::test]
    fn test_buffer_alloc() {
        let mut buffer: MessageMilleGrillesBufferAlloc<CONST_NOMBRE_CERTIFICATS_MAX> = MessageMilleGrillesBufferAlloc::new();
        buffer.buffer.extend(MESSAGE_1.as_bytes());
        let mut parsed = buffer.parse().unwrap();
        debug!("Contenu\n{}", parsed.contenu_escaped);
        parsed.verifier_signature().unwrap();
        debug!("Parsed id: {}", parsed.id);
    }

    #[cfg(feature = "optional-defaults")]
    #[test_log::test]
    fn test_parse_contenu() {
        let mut buffer: MessageMilleGrillesBufferAlloc<CONST_NOMBRE_CERTIFICATS_MAX> = MessageMilleGrillesBufferAlloc::new();
        buffer.buffer.extend(MESSAGE_1.as_bytes());
        let parsed = buffer.parse().unwrap();
        debug!("Contenu parsed : {:?}", parsed.contenu_escaped);
        assert!(serde_json::from_str::<Value>(parsed.contenu_escaped.as_ref()).is_err());

        // let contenu_test = parsed.contenu.replace("\\\"", "\"");
        // let contenu: Value = serde_json::from_str(contenu_test.as_str()).unwrap();
        // let contenu_escaped: Result<std::string::String, std::string::String> = (JsonEscapeIter { s: parsed.contenu.chars() }).collect();
        // let contenu: Value = serde_json::from_str(contenu_escaped.unwrap().as_str()).unwrap();
        let contenu: Value = {
            let buffer_contenu = parsed.contenu().unwrap();
            buffer_contenu.deserialize().unwrap()
        };
        debug!("Contenu value : {:?}", contenu);

        // let escapeIter = JsonEscapeIter { s: parsed.contenu.chars() };
        // let reader = JsonEscapeIterAsRead::new(mapIter);
        // let contenu_escaped_reader: Value = serde_json::from_reader(reader).unwrap();
        // debug!("Contenu value escaped reader : {:?}", contenu);
    }

    #[cfg(feature = "optional-defaults")]
    #[test_log::test]
    fn test_message_2() {
        let mut buffer: MessageMilleGrillesBufferAlloc<CONST_NOMBRE_CERTIFICATS_MAX> = MessageMilleGrillesBufferAlloc::new();
        buffer.buffer.extend(MESSAGE_2.as_bytes());
        let mut parsed = buffer.parse().unwrap();

        let value_hachage = json!([
            &parsed.pubkey,
            parsed.estampille.timestamp(),
            parsed.kind.clone() as isize,
            parsed.contenu_escaped,
            &parsed.routage,
        ]);

        // Comparer avec ancienne methode (serde)
        let vec_hachage = serde_json::to_string(&value_hachage).unwrap();
        debug!("String hachage : {}", vec_hachage);
        let mut hacheur = HacheurBlake2s256::new();
        hacheur.update(vec_hachage.as_bytes());
        let hachage = hacheur.finalize();
        let hachage = hex::encode(hachage);
        debug!("Hachage calcule avec serde : {}", hachage);

        parsed.verifier_signature().unwrap();
        debug!("Parsed id: {}", parsed.id);
    }

    #[test_log::test]
    fn test_parse_message_builder() {
        let message_parsed = MessageMilleGrillesRefDefault::parse(crate::messages_structs::messages_structs_tests::MESSAGE_1).unwrap();
        info!("test_parse_message\nid: {}\nestampille: {}", message_parsed.id, message_parsed.estampille);
        assert_eq!("d49a375c980f1e70cdea697664610d70048899d1428909fdc29bd29cfc9dd1ca", message_parsed.id);
        assert_eq!("9ff0c6443c9214ab9e8ee2d26b3ba6453e7f4f5f59477343e1b0cd747535005b13d453922faad1388e65850a1970662a69879b1b340767fb9f4bda6202412204", message_parsed.signature);
        assert_eq!(MessageKind::Evenement, message_parsed.kind);
    }

    #[test_log::test]
    fn test_build_into_u8() {
        let contenu = "Le contenu a inclure";
        let estampille = DateTime::from_timestamp(1710338722, 0).unwrap();
        let signing_key = SigningKey::from_bytes(b"01234567890123456789012345678901");
        let routage = RoutageMessage::for_action("Test", "test");
        let mut certificat: Vec<&str, CONST_NOMBRE_CERTIFICATS_MAX> = Vec::new();
        certificat.push("CERTIFICAT 1").unwrap();
        certificat.push("CERTIFICAT 2").unwrap();

        let generateur = MessageMilleGrillesBuilderDefault::new(MessageKind::Commande, contenu)
            .estampille(estampille)
            .signing_key(&signing_key)
            .routage(routage)
            .certificat(certificat);

        let mut buffer: Vec<u8, CONST_BUFFER_MESSAGE_MIN> = Vec::new();
        let mut message = generateur.build_into(&mut buffer).unwrap();
        assert!(message.verifier_signature().is_ok());

        assert_eq!("305d8a90809399e68de9244bbb82d4589571be4b6566eb7ef06fde3fdb0fa418", message.id);
        assert_eq!("7bc3079518ed11da0336085bf6962920ff87fb3c4d630a9b58cb6153674f5dd6", message.pubkey);
        assert_eq!(estampille.timestamp(), message.estampille.timestamp());
    }

    #[cfg(feature = "alloc")]
    #[test_log::test]
    fn test_build_into_alloc() {
        let contenu = "{\"contenu\":\"Le contenu a inclure\"}";
        debug!("Contenu initial\n{}", contenu);
        let estampille = DateTime::from_timestamp(1710338722, 0).unwrap();
        let signing_key = SigningKey::from_bytes(b"01234567890123456789012345678901");
        let routage = RoutageMessage::for_action("Test", "test");
        let mut certificat: Vec<&str, CONST_NOMBRE_CERTIFICATS_MAX> = Vec::new();
        certificat.push("CERTIFICAT 1").unwrap();
        certificat.push("CERTIFICAT 2").unwrap();

        let generateur = MessageMilleGrillesBuilderDefault::new(MessageKind::Commande, contenu)
            .estampille(estampille)
            .signing_key(&signing_key)
            .routage(routage)
            .certificat(certificat);

        let mut buffer: std::vec::Vec<u8> = std::vec::Vec::new();
        {
            let mut message_ref = generateur.build_into_alloc(&mut buffer).unwrap();
            debug!("Message ref contenu\n{}", message_ref.contenu_escaped);
            assert!(message_ref.verifier_signature().is_ok());
            assert_eq!("03bed2d56baa397dae02c4ffc267f9d71aa1f78f38e64cd03b93461d5c19fc4c", message_ref.id);
            assert_eq!("7bc3079518ed11da0336085bf6962920ff87fb3c4d630a9b58cb6153674f5dd6", message_ref.pubkey);
            assert_eq!(estampille.timestamp(), message_ref.estampille.timestamp());
        }
        debug!("test_build_into_vec Vec buffer :\n{}", from_utf8(buffer.as_slice()).unwrap());
        buffer.clear();
    }

    #[cfg(feature = "alloc")]
    #[test_log::test]
    fn test_parse_owned() {
        let mut buffer: MessageMilleGrillesBufferAlloc<CONST_NOMBRE_CERTIFICATS_MAX> = MessageMilleGrillesBufferAlloc::new();
        buffer.buffer.extend(MESSAGE_1.as_bytes());
        let parsed = buffer.parse().unwrap();

        let message_id = parsed.id.to_string();

        let message_owned: MessageMilleGrillesOwned = buffer.parse_to_owned().unwrap();
        assert_eq!(message_id, message_owned.id);

        let attachements = message_owned.attachements.as_ref().unwrap();
        assert_eq!(2, attachements.len());

        // Faire un cycle pour s'assurer que le processus est complet
        let buffer2: MessageMilleGrillesBufferAlloc<CONST_NOMBRE_CERTIFICATS_MAX> = message_owned.try_into().unwrap();
        let parsed2 = buffer2.parse().unwrap();
        assert_eq!(parsed.contenu_escaped, parsed2.contenu_escaped);
    }

    #[cfg(feature = "alloc")]
    #[test_log::test]
    fn test_into_owned() {
        let mut buffer: MessageMilleGrillesBufferAlloc<CONST_NOMBRE_CERTIFICATS_MAX> = MessageMilleGrillesBufferAlloc::new();
        buffer.buffer.extend(MESSAGE_1.as_bytes());
        let parsed = buffer.parse().unwrap();

        let message_id = parsed.id.to_string();

        let message_owned: MessageMilleGrillesOwned = parsed.clone().try_into().unwrap();
        assert_eq!(message_id, message_owned.id);

        // Faire un cycle pour s'assurer que le processus est complet
        let buffer2: MessageMilleGrillesBufferAlloc<CONST_NOMBRE_CERTIFICATS_MAX> = message_owned.try_into().unwrap();
        let parsed2 = buffer2.parse().unwrap();
        assert_eq!(parsed.contenu_escaped, parsed2.contenu_escaped);
    }

    #[cfg(feature = "alloc")]
    #[test_log::test]
    fn test_owned_hachage() {
        let mut buffer: MessageMilleGrillesBufferAlloc<CONST_NOMBRE_CERTIFICATS_MAX> = MessageMilleGrillesBufferAlloc::new();
        buffer.buffer.extend(MESSAGE_1.as_bytes());
        let mut message_owned = buffer.parse_to_owned().unwrap();
        message_owned.verifier_signature().unwrap();
    }

    #[cfg(feature = "alloc")]
    #[test_log::test]
    fn test_encrypt_into_alloc() {
        let contenu = "{\"contenu\":\"Le contenu a inclure\"}";
        debug!("Contenu initial\n{}", contenu);
        let estampille = DateTime::from_timestamp(1710338722, 0).unwrap();
        let signing_key = SigningKey::from_bytes(b"01234567890123456789012345678901");
        let routage = RoutageMessage::for_action("Test", "test");
        let mut certificat: Vec<&str, CONST_NOMBRE_CERTIFICATS_MAX> = Vec::new();
        certificat.push("CERTIFICAT 1").unwrap();
        certificat.push("CERTIFICAT 2").unwrap();

        let cipher = CipherMgs4::new().unwrap();

        let generateur = MessageMilleGrillesBuilderDefault::new(MessageKind::CommandeInterMillegrille, contenu)
            .estampille(estampille)
            .signing_key(&signing_key)
            .routage(routage)
            .origine("ORIGINE")
            .certificat(certificat);

        let mut buffer: std::vec::Vec<u8> = std::vec::Vec::new();
        {
            // let mut message_ref = generateur.build_into_alloc(&mut buffer).unwrap();
            let mut message_ref = generateur.encrypt_into_alloc(&mut buffer, cipher).unwrap();
            debug!("Message ref contenu\n{}", message_ref.contenu_escaped);
            assert!(message_ref.verifier_signature().is_ok());
            assert_eq!(estampille.timestamp(), message_ref.estampille.timestamp());
        }
        debug!("test_build_into_vec Vec buffer :\n{}", from_utf8(buffer.as_slice()).unwrap());
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct ContenuMessageDechiffre {
        texte: String<2048>,
    }

    #[cfg(feature = "alloc")]
    #[test_log::test]
    fn test_encrypt_into_alloc_certs() {
        let contenu = ContenuMessageDechiffre { texte: "Le contenu a inclure".try_into().unwrap() };
        let contenu_str = serde_json::to_string(&contenu).unwrap();

        debug!("Contenu initial\n{:?}", contenu);
        let estampille = DateTime::from_timestamp(1710338722, 0).unwrap();
        let signing_key = SigningKey::from_bytes(b"01234567890123456789012345678901");
        let routage = RoutageMessage::for_action("Test", "test");

        let enveloppe_ca = EnveloppeCertificat::from_file(
            &PathBuf::from("/var/opt/millegrilles/configuration/pki.millegrille.cert")).unwrap();

        let enveloppe_core = EnveloppePrivee::from_files(
            &PathBuf::from("/var/opt/millegrilles/secrets/pki.core.cert"),
            &PathBuf::from("/var/opt/millegrilles/secrets/pki.core.cle"),
            &PathBuf::from("/var/opt/millegrilles/configuration/pki.millegrille.cert")
        ).unwrap();

        let chaine_pem = enveloppe_core.enveloppe_pub.chaine_pem().unwrap();
        let mut enveloppe_core_pem: Vec<&str, 4> = Vec::new();
        for cert in &chaine_pem {
            enveloppe_core_pem.push(cert.as_str()).unwrap();
        }

        let enveloppes = vec![
            enveloppe_core.enveloppe_pub.as_ref()
        ];

        let cipher = CipherMgs4::with_ca(&enveloppe_ca).unwrap();

        let mut buffer: std::vec::Vec<u8> = std::vec::Vec::new();
        {
            let generateur = MessageMilleGrillesBuilderDefault::new(MessageKind::CommandeInterMillegrille, contenu_str.as_str())
                .estampille(estampille)
                .signing_key(&signing_key)
                .routage(routage)
                .origine("ORIGINE")
                .certificat(enveloppe_core_pem)
                .cles_chiffrage(enveloppes);

            // let mut message_ref = generateur.build_into_alloc(&mut buffer).unwrap();
            let mut message_ref = generateur.encrypt_into_alloc(&mut buffer, cipher).unwrap();
            debug!("Message ref contenu\n{}", message_ref.contenu_escaped);
            assert!(message_ref.verifier_signature().is_ok());
            assert_eq!(estampille.timestamp(), message_ref.estampille.timestamp());
            assert_eq!(2, message_ref.dechiffrage.unwrap().cles.unwrap().len());
        }
        debug!("test_build_into_vec Vec buffer :\n{}", from_utf8(buffer.as_slice()).unwrap());

        // Decrypt
        let message_buffer = MessageMilleGrillesBufferDefault::from(buffer);
        let message_ref = message_buffer.parse().unwrap();
        let data_dechiffre: ContenuMessageDechiffre = message_ref.dechiffrer(&enveloppe_core).unwrap();
        debug!("Data dechiffre vec (len: {}):\n{:?}", data_dechiffre.texte.len(), data_dechiffre);
    }

    #[derive(Serialize)]
    struct ContenuMessage<'a> {
        texte: &'a str,
    }

    #[cfg(feature = "alloc")]
    #[test_log::test]
    fn test_utf8_speciaux() {
        let contenu = ContenuMessage { texte: TEST_STRING_UTF8_1 };
        let contenu_str = serde_json::to_string(&contenu).unwrap();
        let routage = RoutageMessage::for_action("Test", "test");
        let signing_key = SigningKey::from_bytes(b"01234567890123456789012345678901");

        let mut message_vec = std::vec::Vec::new();
        let mut message_owned: MessageMilleGrillesOwned = {
            let mut message_ref = MessageMilleGrillesRefDefault::builder(MessageKind::Commande, contenu_str.as_str())
                .routage(routage)
                .signing_key(&signing_key)
                .build_into_alloc(&mut message_vec).unwrap();

            // assert_eq!("362543fd839dfcf635406462691ae07dfbd287f14d37df7b247e360b5fb3b8c4", message_ref.id);

            message_ref.verifier_signature().unwrap();

            message_ref.try_into().unwrap()
        };

        info!("Contenu message \n{}", from_utf8(message_vec.as_slice()).unwrap());

        message_owned.verifier_signature().unwrap();
    }
}