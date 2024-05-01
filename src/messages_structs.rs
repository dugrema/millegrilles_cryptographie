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
use x509_parser::nom::InputIter;

use crate::chiffrage_cles::{Cipher, CleChiffrageX25519, CleDechiffrageX25519Impl, Decipher};
use crate::chiffrage_mgs4::DecipherMgs4;
use crate::ed25519::{MessageId, signer_into, verifier};
use crate::error::Error;
use crate::hachages::{HacheurInterne, HacheurBlake2s256};
use crate::maitredescles::SignatureDomaines;
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
    pub cle_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cles: Option<FnvIndexMap<&'a str, &'a str, CONST_NOMBRE_CLES_MAX>>,
    pub format: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hachage: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureDomaines>,
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
            signature: self.signature.clone(),
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
    pub signature: Option<SignatureDomaines>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<std::string::String>,
}

impl DechiffrageInterMillegrilleOwned {
    pub fn to_cle_dechiffrage(&self, enveloppe_privee: &EnveloppePrivee)
                          -> Result<CleDechiffrageX25519Impl, Error>
    {
        let dechiffrage_ref: DechiffrageInterMillegrille = self.try_into()?;
        dechiffrage_ref.to_cle_dechiffrage(enveloppe_privee)
    }
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
            signature: self.signature.clone(),
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
        let json_iter = JsonUnescapeIter {
            s: self.contenu_escaped.chars(),
            remettre_backslash: false,
            chars_pending: None,
        };
        let contenu_string: Result<std::string::String, Error> = json_iter.collect();
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
        let data_dechiffre = match decipher.gz_to_vec(data_chiffre.as_slice()) {
            Ok(inner) => inner,
            Err(e) => Err(Error::String(format!("MessageMilleGrillesRef.dechiffrer Erreur decompreesion gzip du contenu : {:?}", e)))?
        };
        Ok(serde_json::from_slice(data_dechiffre.as_slice())?)
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
            Err(Error::Str("MessageMilleGrillesRef verifier_signature Invalide"))?
        }

        // Verifier le hachage du message
        let hacheur = HacheurMessage::from(&*self);
        let hachage_string = hacheur.hacher()?;
        if self.id != hachage_string.as_str() {
            self.contenu_valide = Some((false, false));
            error!("MessageMilleGrillesRef verifier_signature hachage invalide : id: {}, calcule: {}", self.id, hachage_string);
            Err(Error::Str("MessageMilleGrillesRef verifier_signature hachage invalide"))?
        }

        // Extraire cle publique (bytes de pubkey) pour verifier la signature
        let mut buf_pubkey = [0u8; 32];
        hex::decode_to_slice(self.pubkey, &mut buf_pubkey)?;
        let verifying_key = VerifyingKey::from_bytes(&buf_pubkey)?;

        // Extraire la signature (bytes de sig)
        let mut hachage_bytes = [0u8; 32] as MessageId;
        if let Err(e) = hex::decode_to_slice(self.id, &mut hachage_bytes) {
            error!("MessageMilleGrillesRef verifier_signature Erreur hex {:?}", e);
            self.contenu_valide = Some((false, true));
            Err(Error::Str("MessageMilleGrillesRef verifier_signature:E1"))?
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
            Err(Error::Str("MessageMilleGrillesOwned verifier_signature Invalide"))?
        }

        // Verifier le hachage du message
        let hacheur = HacheurMessage::try_from(&*self)?;
        let hachage_string = hacheur.hacher()?;
        if self.id.as_str() != hachage_string.as_str() {
            self.contenu_valide = Some((false, false));
            error!("MessageMilleGrillesOwned verifier_signature hachage invalide : id: {}, calcule: {}", self.id, hachage_string);
            Err(Error::Str("MessageMilleGrillesOwned verifier_signature hachage invalide"))?
        }

        // Extraire cle publique (bytes de pubkey) pour verifier la signature
        let mut buf_pubkey = [0u8; 32];
        hex::decode_to_slice(&self.pubkey, &mut buf_pubkey)?;
        let verifying_key = VerifyingKey::from_bytes(&buf_pubkey)?;

        // Extraire la signature (bytes de sig)
        let mut hachage_bytes = [0u8; 32] as MessageId;
        if let Err(e) = hex::decode_to_slice(&self.id, &mut hachage_bytes) {
            error!("verifier_signature Erreur hex {:?}", e);
            self.contenu_valide = Some((false, true));
            Err(Error::Str("MessageMilleGrillesOwned verifier_signature:E1"))?
        }

        // Verifier la signature
        if ! verifier(&verifying_key, &hachage_bytes, &self.signature) {
            self.contenu_valide = Some((false, true));
            Err(Error::Str("MessageMilleGrillesOwned verifier_signature signature invalide"))?
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

struct JsonUnescapeIter<'a> {
    /// Characteres en input
    s: std::str::Chars<'a>,
    /// Si true, on remet le backslash dans l'output.
    remettre_backslash: bool,
    /// Permet de conserver des caracteres a emettre.
    chars_pending: Option<Vec<char, 4>>,
}

impl<'a> Iterator for JsonUnescapeIter<'a> {
    type Item = Result<char, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(pending) = self.chars_pending.as_mut() {
            let char_pending = pending.remove(0);
            if pending.len() == 0 {
                self.chars_pending = None
            }
            return Some(Ok(char_pending))
        }

        match self.s.next() {
            Some(c) => match c {
                '\\' => {
                    let c = match self.s.next() {
                        Some(c) => match c {
                            'n' | 'r' | 'b' | 'f' | 't' | '\\' | '/' | '"' => {
                                Some(c)
                            },
                            'u' => {
                                // Aller chercher les 4 chars suivants pour extraire la valeur unicode
                                let mut chars_unicode: String<4> = String::new();
                                for _ in 0..4 {
                                    match self.s.next() {
                                        Some(c) => {
                                            if let Err(_) = chars_unicode.push(c) {
                                                return Some(Err(Error::Str("hacher_contenu Erreur decodage unicode, trop de chars")))
                                            }
                                        },
                                        None => return Some(Err(Error::Str("hacher_contenu Sequence unicode incomplete")))
                                    }
                                }

                                // Decoder la string
                                let char_radix = match u32::from_str_radix(chars_unicode.as_str(), 16) {
                                    Ok(inner) => inner,
                                    Err(e) => {
                                        return Some(Err(Error::String(format!("hacher_contenu Erreur formattage char u32 {:?}", e))));
                                    }
                                };

                                // Convertir en char
                                let char_unicode = match char::from_u32(char_radix) {
                                    Some(inner) => inner,
                                    None => return Some(Err(Error::Str("hacher_contenu Erreur decodage char u32")))
                                };

                                // On retourne immediatement, on s'est debarrasse de l'escape \uXXXX
                                return Some(Ok(char_unicode))
                            },
                            _ => return Some(Err(Error::Str("Char escape invalide"))),
                        }
                        None => return Some(Err(Error::Str("Char escape a la fin de la str")))
                    };

                    if self.remettre_backslash {
                        if let Some(c) = c {
                            let mut vec_pending = Vec::new();
                            vec_pending.push(c).expect("push");
                            self.chars_pending = Some(vec_pending);
                        }
                        return Some(Ok('\\'))
                    } else {
                        match c {
                            Some(c) => Some(Ok(c)),
                            None => None
                        }
                    }
                },
                c => Some(Ok(c))
            },
            None => None
        }
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

    pub fn parse(buffer: &'a str) -> Result<Self, Error> {
        let message_parsed: Self = match serde_json_core::from_slice(buffer.as_bytes()) {
            Ok(inner) => inner.0,
            Err(e) => {
                error!("MessageMilleGrilleBuffer serde_json_core::from_slice {:?}", e);
                Err(Error::Str("MessageMilleGrillesRef Erreur serde_json_core::from_slice"))?
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

    fn hacher_base(&mut self) -> Result<(), Error> {
        // Hacher le debut d'un array 'json' -> ["pubkey",estampille,kind,"contenu"

        let separateur_bytes= ",".as_bytes();
        let guillemet_bytes = "\"".as_bytes();

        self.hacheur.update("[\"".as_bytes());
        self.hacheur.update(self.pubkey.as_bytes());
        self.hacheur.update(guillemet_bytes);

        // L'estampille (epoch secs) prend 10 chars. Mettre 12 pour support futur.
        let estampille_str: String<12> = String::try_from(self.estampille.timestamp())
            .map_err(|_| Error::Str("HacheurMessage.hacher_base Erreur conversion estampille"))?;
        self.hacheur.update(separateur_bytes);
        self.hacheur.update(estampille_str.as_bytes());

        let kind_int = self.kind.clone() as u8;
        let kind_str: String<3> = String::try_from(kind_int)
            .map_err(|_| Error::Str("HacheurMessage.hacher_base Erreur conversion kind"))?;  // 3 chars pour kind (<100)
        self.hacheur.update(separateur_bytes);
        self.hacheur.update(kind_str.as_bytes());

        // Iterer sur les chars, effectue l'escape des characteres correctement.
        self.hacheur.update(separateur_bytes);
        self.hacheur.update(guillemet_bytes);
        self.hacher_contenu()?;
        self.hacheur.update(guillemet_bytes);

        Ok(())
    }

    fn hacher_contenu(&mut self) -> Result<(), Error> {
        let mut buffer_char = [0u8; 4];

        if self.contenu_escaped {
            // Contenu deja escaped - parcourir pour convertir unicode \uXXXX
            let mut iter_json = JsonUnescapeIter {
                s: self.contenu.chars(),
                remettre_backslash: true,
                chars_pending: None,
            };
            while let Some(c) = iter_json.next() {
                let c = c?;
                let char2 = c.encode_utf8(&mut buffer_char);
                self.hacheur.update(char2.as_bytes());
            }
        } else {
            // Contenu sans escape, on ajoute les \ au besoin
            let escape_backslash = "\\".as_bytes();
            let mut iter_chars = self.contenu.iter_elements();
            while let Some(c) = iter_chars.next() {
                match c {
                    '"' | '\\' => {
                        // Escape backslash
                        self.hacheur.update(escape_backslash);
                    }
                    _ => ()
                }
                let char2 = c.encode_utf8(&mut buffer_char);
                self.hacheur.update(char2.as_bytes());
            }
        }

        Ok(())
    }

    fn hacher_routage(&mut self) -> Result<(), Error> {
        let mut buffer = [0u8; 200];
        let routage_size = serde_json_core::to_slice(self.routage.as_ref().unwrap(), &mut buffer)?;
        debug!("Routage\n{}", from_utf8(&buffer[..routage_size])?);
        self.hacheur.update(&buffer[..routage_size]);
        Ok(())
    }

    fn hacher_premigration(&mut self) -> Result<(), Error> {
        let mut buffer = [0u8; 500];
        let routage_size = serde_json_core::to_slice(self.pre_migration.as_ref().unwrap(), &mut buffer)?;
        debug!("PreMigration\n{}", from_utf8(&buffer[..routage_size])?);
        self.hacheur.update(&buffer[..routage_size]);
        Ok(())
    }

    fn hacher_dechiffrage(&mut self) -> Result<(), Error> {
        let mut buffer = [0u8; 2000];

        let mut dechiffrage_copy = match self.dechiffrage.clone() {
            Some(inner) => inner,
            None => return Ok(()) // Rien a faire, on a un espace vide
        };

        if let Some(cles) = dechiffrage_copy.cles.as_mut() {
            if cles.len() > 1 {
                // Trier fingerprints des cles
                let mut sorted_keys: Vec<&str, CONST_NOMBRE_CLES_MAX> = cles.keys().map(|k| *k).collect();
                sorted_keys.sort();
                // Re-inserer les cles dans le bon ordre
                let values: FnvIndexMap<&str, &str, CONST_NOMBRE_CLES_MAX> = cles.iter().map(|(k,v)| (*k, *v)).collect();
                cles.clear();
                for key in sorted_keys {
                    match values.get(key) {
                        Some(inner) => {
                            cles.insert(key, *inner).map_err(|_| Error::Str("hacher_dechiffrage Erreur mapping cles.insert"))?;
                        },
                        None => Err(Error::Str("hacher_dechiffrage Erreur sort key, valeur introuvable"))?
                    }
                }
            }
        }

        let dechiffrage_size = serde_json_core::to_slice(&dechiffrage_copy, &mut buffer)?;
        debug!("Dechiffrage\n{}", from_utf8(&buffer[..dechiffrage_size])?);
        self.hacheur.update(&buffer[..dechiffrage_size]);

        Ok(())
    }

    pub fn hacher(mut self) -> Result<String<64>, Error> {
        // Effectuer le hachage de : ["pubkey", estampille, kind, "contenu"
        self.hacher_base()?;

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
                self.hacher_routage()?;
            },
            MessageKind::ReponseChiffree => {
                // [pubkey, estampille, kind, contenu, routage, dechiffrage]
                if self.dechiffrage.is_none() {
                    error!("HacheurMessage::hacher Dechiffrage requis");
                    Err(Error::Str("HacheurMessage::hacher:E2"))?
                }
                self.hacheur.update(virgule);
                self.hacher_dechiffrage()?;
            },
            MessageKind::TransactionMigree => {
                // [pubkey, estampille, kind, contenu, routage, pre_migration]
                if self.routage.is_none() || self.pre_migration.is_none() {
                    error!("HacheurMessage::hacher Champs routage et pre-migration requis");
                    Err(Error::Str("HacheurMessage::hacher:E3"))?
                }

                // Ajouter routage,pre-migration
                self.hacheur.update(virgule);
                self.hacher_routage()?;
                self.hacheur.update(virgule);
                self.hacher_premigration()?;
            },
            MessageKind::CommandeInterMillegrille => {
                // [pubkey, estampille, kind, contenu, routage, origine, dechiffrage]
                if self.routage.is_none() || self.origine.is_none() || self.dechiffrage.is_none() {
                    error!("HacheurMessage::hacher Routage/origine/dechiffrage requis (routage: {:?}, origine: {:?}, dechiffrage: {:?})",
                        self.routage, self.origine, self.dechiffrage);
                    Err(Error::Str("HacheurMessage::hacher:E4"))?
                }
                self.hacheur.update(virgule);
                self.hacher_routage()?;
                self.hacheur.update(virgule);

                self.hacheur.update(guillemet);
                self.hacheur.update(self.origine.unwrap().as_bytes());
                self.hacheur.update(guillemet);
                self.hacheur.update(virgule);

                self.hacher_dechiffrage()?;
            },
        }

        // Fermer array de hachage
        self.hacheur.update("]".as_bytes());

        let mut hachage = [0u8; 32];
        self.hacheur.finalize_into(&mut hachage);

        let mut output_str = [0u8; 64];
        hex::encode_to_slice(hachage, &mut output_str)?;
        let hachage_str = from_utf8(&output_str)?;

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
            contenu: value.contenu.as_str(),
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
            Err(_) => Err("MessageMilleGrilles::parse:E2")
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
            Err(_) => Err("MessageMilleGrilles::parse:E2")
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
        hex::encode_to_slice(pubkey_bytes, &mut buf_pubkey_str)?;
        let pubkey_str = from_utf8(&buf_pubkey_str)?;

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
        let message_ref = MessageMilleGrillesRef::parse(from_utf8(buffer.as_slice())?)?;

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
            signature: None,
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
        hex::encode_to_slice(pubkey_bytes, &mut buf_pubkey_str)?;
        let pubkey_str = from_utf8(&buf_pubkey_str)?;

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
        buffer.resize_default(buffer.capacity()).map_err(|()| Error::Str("build_into Erreur resize default"))?;
        let taille = match serde_json_core::to_slice(&message_ref, buffer) {
            Ok(taille) => taille,
            Err(e) => {
                error!("build_into Erreur serde_json_core::to_slice {:?}", e);
                Err(Error::Str("build_into:E1"))?
            }
        };
        buffer.truncate(taille);  // S'assurer que le Vec a la taille utilisee
        debug!("Message serialise\n{:?}", from_utf8(buffer)?);

        // Parse une nouvelle reference a partir du nouveau buffer
        // Permet de transferer l'ownership des references vers l'objet buffer
        Ok(MessageMilleGrillesRef::parse(from_utf8(buffer)?)?)
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
    use crate::samples::*;
    use std::path::PathBuf;
    use log::info;
    use serde_json::json;
    use crate::chiffrage_mgs4::CipherMgs4;

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

        // Retirer les guillemets pour simuler un contenu qui provient directement d'un pointeur message
        let contenu_stripped = &contenu[1..contenu.len()-1];

        // Escape to string
        debug!("Contenu doc json:\n{}", contenu_stripped);
        let hacheur = HacheurMessage::new(pubkey, &estampille, MessageKind::Reponse, contenu_stripped);
        let resultat = hacheur.hacher().unwrap();
        assert_eq!("3873562f090d472e6309b02ff2762959e72d24f76919ee0ac62d1d39e1e4a159", resultat);
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
    fn test_verifier_signature_5() {
        let mut message_parsed = MessageMilleGrillesRefDefault::parse(MESSAGE_5).unwrap();

        let json_iter = JsonUnescapeIter {
            s: message_parsed.contenu_escaped.chars(),
            remettre_backslash: true,
            chars_pending: None
        };
        let contenu_parsed: std::string::String = json_iter.map(|c| c.unwrap()).collect();
        debug!("Contenu parsed JsonIter\n{}", contenu_parsed);

        message_parsed.verifier_signature().unwrap();
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

        let contenu: Value = {
            let buffer_contenu = parsed.contenu().unwrap();
            buffer_contenu.deserialize().unwrap()
        };
        debug!("Contenu value : {:?}", contenu);
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

        let json_iter = JsonUnescapeIter {
            s: message_owned.contenu.chars(),
            remettre_backslash: true,
            chars_pending: None
        };
        let contenu_parsed: std::string::String = json_iter.map(|c| c.unwrap()).collect();
        debug!("Contenu parsed JsonIter\n{}", contenu_parsed);

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

    #[cfg(feature = "optional-defaults")]
    #[test_log::test]
    fn test_message_6() {
        let mut buffer: MessageMilleGrillesBufferAlloc<CONST_NOMBRE_CERTIFICATS_MAX> = MessageMilleGrillesBufferAlloc::new();
        buffer.buffer.extend(MESSAGE_6.as_bytes());
        buffer.parse().unwrap();

        let mut message_owned = buffer.parse_to_owned().unwrap();
        message_owned.verifier_signature().unwrap();
    }
}