use core::str::{from_utf8, FromStr};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_repr::{Serialize_repr, Deserialize_repr};
use heapless::{Vec, FnvIndexMap, String};
use log::{debug, error};
use crate::generateur::MessageMilleGrillesBuilder;
use crate::hachages::{HacheurInterne, HacheurBlake2s256};

const CONST_NOMBRE_CERTIFICATS_MAX: usize = 4;
const CONST_NOMBRE_CLES_MAX: usize = 8;

// La taille du buffer avec no_std (microcontrolleur) est 24kb. Sinon taille max message est 10mb.
#[cfg(not(feature = "std"))]
const CONST_BUFFER_MESSAGE: usize = 24 * 1024;
#[cfg(feature = "std")]
const CONST_BUFFER_MESSAGE: usize = 10 * 1024 * 1024;

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

#[derive(Clone, Debug, Serialize, Deserialize)]
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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

    /// Contenu du message en format json-string
    pub contenu: &'a str,

    /// Information de routage de message (optionnel, depend du kind)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routage: Option<RoutageMessage<'a>>,

    // /// Information de migration (e.g. ancien format, MilleGrille tierce, etc).
    // #[serde(rename = "pre-migration", skip_serializing_if = "Option::is_none")]
    // pub pre_migration: Option<FnvIndexMap<&'a str, Value, 10>>,

    /// IDMG d'origine du message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origine: Option<&'a str>,

    /// Information de dechiffrage pour contenu chiffre
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dechiffrage: Option<DechiffrageInterMillegrille<'a>>,

    /// Signature ed25519 encodee en hex
    #[serde(rename = "sig")]
    pub signature: &'a str,

    /// Chaine de certificats en format PEM.
    #[serde(rename = "certificat", skip_serializing_if = "Option::is_none")]
    pub certificat: Option<Vec<&'a str, CONST_NOMBRE_CERTIFICATS_MAX>>,

    /// Certificat de millegrille (root).
    #[serde(rename = "millegrille", skip_serializing_if = "Option::is_none")]
    pub millegrille: Option<&'a str>,

    // /// Attachements au message. Traite comme attachments non signes (doivent etre validable separement).
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub attachements: Option<FnvIndexMap<&'a str, Value, 32>>,

    #[serde(skip)]
    contenu_valide: Option<(bool, bool)>,
}

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

    pub fn builder(kind: MessageKind, contenu: &'a str) -> MessageMilleGrillesBuilder<'a, C> {
        MessageMilleGrillesBuilder::new(kind, contenu)
    }
}

pub struct HacheurMessage<'a> {
    hacheur: HacheurBlake2s256,
    pubkey: &'a str,
    estampille: &'a DateTime<Utc>,
    kind: MessageKind,
    contenu: &'a str,
    routage: Option<&'a RoutageMessage<'a>>,
    // pre_migration: Option<FnvIndexMap<&'a str, Value, 10>>,
    origine: Option<&'a str>,
    dechiffrage: Option<&'a DechiffrageInterMillegrille<'a>>,
}

impl<'a> HacheurMessage<'a> {

    pub fn new(pubkey: &'a str, estampille: &'a DateTime<Utc>, kind: MessageKind, contenu: &'a str) -> Self {
        Self {
            hacheur: HacheurBlake2s256::new(),
            pubkey,
            estampille,
            kind,
            contenu,
            routage: None,
            origine: None,
            dechiffrage: None,
        }
    }

    pub fn routage(mut self, routage: &'a RoutageMessage<'a>) -> Self {
        self.routage = Some(routage);
        self
    }

    pub fn origine(mut self, origine: &'a str) -> Self {
        self.origine = Some(origine);
        self
    }

    pub fn dechiffrage(mut self, dechiffrage: &'a DechiffrageInterMillegrille<'a>) -> Self {
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

        let estampille_str: String<12> = String::try_from(self.estampille.timestamp()).unwrap();
        self.hacheur.update(separateur_bytes);
        self.hacheur.update(estampille_str.as_bytes());

        let kind_int = self.kind.clone() as u8;
        let kind_str: String<3> = String::try_from(kind_int).unwrap();
        self.hacheur.update(separateur_bytes);
        self.hacheur.update(kind_str.as_bytes());

        // Iterer sur les chars, effectue l'escape des characteres correctement.
        let mut buffer_char = [0u8; 4];
        self.hacheur.update(separateur_bytes);
        self.hacheur.update(guillemet_bytes);
        for c in self.contenu.chars() {
            let char2 = c.encode_utf8(&mut buffer_char);
            self.hacheur.update(char2.as_bytes());
        }
        self.hacheur.update(guillemet_bytes);
    }

    fn hacher_routage(&mut self) {
        let mut buffer = [0u8; 200];
        let routage_size = serde_json_core::to_slice(self.routage.unwrap(), &mut buffer).unwrap();
        debug!("Routage\n{}", from_utf8(&buffer[..routage_size]).unwrap());
        self.hacheur.update(&buffer[..routage_size]);
    }

    fn hacher_dechiffrage(&mut self) {
        let mut buffer = [0u8; 2000];
        let dechiffrage_size = serde_json_core::to_slice(self.routage.unwrap(), &mut buffer).unwrap();
        debug!("Dechiffrage\n{}", from_utf8(&buffer[..dechiffrage_size]).unwrap());
        self.hacheur.update(&buffer[..dechiffrage_size]);
    }

    pub fn hacher(mut self) -> Result<String<64>, &'static str> {
        // Effectuer le hachage de : ["pubkey", estampille, kind, "contenu"
        self.hacher_base();

        // Determiner elements additionnels a hacher en fonction du kind
        match self.kind {
            MessageKind::Document | MessageKind::Reponse | MessageKind::ReponseChiffree => {
                // [pubkey, estampille, kind, contenu]
                // Deja fait, rien a ajouter.
            },
            MessageKind::Requete | MessageKind::Commande => {} | MessageKind::Transaction => {} | MessageKind::Evenement => {
                // [pubkey, estampille, kind, contenu, routage]

                if self.routage.is_none() {
                    error!("HacheurMessage::hacher Routage requis (None)");
                    Err("HacheurMessage::hacher:E1")?
                }

                // Ajouter routage
                self.hacheur.update(",".as_bytes());
                self.hacher_routage();
            },
            MessageKind::TransactionMigree => {
                // [pubkey, estampille, kind, contenu, routage, pre_migration]
                panic!("Not implemented")
            },
            MessageKind::CommandeInterMillegrille => {
                // [pubkey, estampille, kind, contenu, routage, origine, dechiffrage]
                if self.routage.is_none() || self.origine.is_none() || self.dechiffrage.is_none() {
                    error!("HacheurMessage::hacher Routage/origine/dechiffrage requis (None)");
                    Err("HacheurMessage::hacher:E2")?
                }
                self.hacheur.update(",".as_bytes());
                self.hacher_routage();
                self.hacheur.update(",".as_bytes());
                self.hacheur.update(self.origine.unwrap().as_bytes());
                self.hacheur.update(",".as_bytes());
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
            Err(()) => Err("HacheurMessage::hacher:E2")?
        }
    }

}

impl<'a, const C: usize> From<&'a MessageMilleGrillesRef<'a, C>> for HacheurMessage<'a> {
    fn from(value: &'a MessageMilleGrillesRef<'a, C>) -> Self {
        HacheurMessage {
            hacheur: HacheurBlake2s256::new(),
            pubkey: value.pubkey,
            estampille: &value.estampille,
            kind: value.kind.clone(),
            contenu: value.contenu,
            routage: value.routage.as_ref(),
            origine: value.origine,
            dechiffrage: value.dechiffrage.as_ref(),
        }
    }
}

/// Convertisseur de date i64 en epoch (secondes)
mod epochseconds {

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

#[cfg(test)]
mod messages_structs_tests {
    use super::*;
    use log::info;

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
      ]
    }"#;

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
        let contenu = "{\"domaine\":\"CoreMaitreDesComptes\",\"exchanges_routing\":null,\"instance_id\":\"f861aafd-5297-406f-8617-f7b8809dd448\",\"primaire\":true,\"reclame_fuuids\":false,\"sous_domaines\":null}";
        let hacheur = HacheurMessage::new(pubkey, &estampille, MessageKind::Reponse, contenu);
        let resultat = hacheur.hacher().unwrap();
        assert_eq!("482f08d4c026e3c1add5f86c77e81e13d96cd1a09df7886852ef33a53f705689", resultat);
    }

    #[test_log::test]
    fn test_hacher_evenement() {
        let message_parsed = MessageMilleGrillesRefDefault::parse(MESSAGE_1).unwrap();
        let hacheur = HacheurMessage::from(&message_parsed);
        let resultat = hacheur.hacher().unwrap();

        // Comparer id au hachage - doit correspondre
        assert_eq!(message_parsed.id, resultat);
    }

}
