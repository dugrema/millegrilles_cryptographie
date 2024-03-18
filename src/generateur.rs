use core::str::{from_utf8, FromStr};
use chrono::{DateTime, Utc};
use log::{debug, error};
use ed25519_dalek::SigningKey;
use heapless::{String, Vec};

use crate::ed25519::{MessageId, signer_into};
use crate::messages_structs::{HacheurMessage, MessageKind, MessageMilleGrillesRef,
                              MessageMilleGrillesRefDefault, RoutageMessage,
                              DechiffrageInterMillegrille,
                              CONST_NOMBRE_CERTIFICATS_MAX};

// const CONST_ELEMS_MAX: usize = 10;
//
// type VecElements<'a> = Vec<&'a [u8], CONST_ELEMS_MAX>;

pub type MessageMilleGrillesBuilderDefault<'a> = MessageMilleGrillesBuilder<'a, CONST_NOMBRE_CERTIFICATS_MAX>;

pub struct MessageMilleGrillesBuilder<'a, const C: usize> {
    estampille: DateTime<Utc>,
    kind: MessageKind,
    contenu: &'a str,
    routage: Option<RoutageMessage<'a>>,
    origine: Option<&'a str>,
    dechiffrage: Option<DechiffrageInterMillegrille<'a>>,
    certificat: Option<Vec<&'a str, C>>,
    millegrille: Option<&'a str>,
    signing_key: &'a SigningKey,
}

impl<'a, const C: usize> MessageMilleGrillesBuilder<'a, C> {

    pub fn new(kind: MessageKind, contenu: &'a str, estampille: DateTime<Utc>, signing_key: &'a SigningKey) -> Self {
        Self {estampille, kind, contenu, routage: None, origine: None, dechiffrage: None, certificat: None, millegrille: None, signing_key}
    }

    pub fn routage(mut self, routage: RoutageMessage<'a>) -> Self {
        self.routage = Some(routage);
        self
    }

    pub fn certificat(mut self, certificat: Vec<&'a str, C>) -> Self {
        self.certificat = Some(certificat);
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

    pub fn millegrille(mut self, millegrille: &'a str) -> Self {
        self.millegrille = Some(millegrille);
        self
    }

    /// Version std avec un Vec qui supporte alloc. Permet de traiter des messages de grande taille.
    #[cfg(feature = "alloc")]
    pub fn build_into_alloc<'b>(self, buffer: &'b mut std::vec::Vec<u8>) -> Result<MessageMilleGrillesRef<'b, C>, &'static str> {
        // Calculer pubkey
        let verifying_key = self.signing_key.verifying_key();
        let pubkey_bytes = verifying_key.as_bytes();
        let mut buf_pubkey_str = [0u8; 64];
        hex::encode_to_slice(pubkey_bytes, &mut buf_pubkey_str).unwrap();
        let pubkey_str = from_utf8(&buf_pubkey_str).unwrap();

        let message_id = self.generer_id(pubkey_str)?;
        let signature = self.signer(message_id.as_str())?;

        let message_ref: MessageMilleGrillesRef<C> = MessageMilleGrillesRef {
            id: message_id.as_str(),
            pubkey: pubkey_str,
            estampille: self.estampille,
            kind: self.kind,
            contenu: self.contenu,
            routage: self.routage,
            #[cfg(feature = "serde_json")]
            pre_migration: None,
            origine: self.origine,
            dechiffrage: self.dechiffrage,
            signature: signature.as_str(),
            certificat: self.certificat,
            millegrille: self.millegrille,
            #[cfg(feature = "serde_json")]
            attachements: None,
            contenu_valide: None,
        };

        // Ecrire dans buffer
        let message_vec = match serde_json::to_vec(&message_ref) {
            Ok(resultat) => resultat,
            Err(e) => {
                error!("build_into Erreur serde_json::to_string {:?}", e);
                Err("build_into:E1")?
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

    pub fn build_into<const B: usize>(self, buffer: &'a mut Vec<u8, B>)
        -> Result<MessageMilleGrillesRef<'a, C>, &'static str>
    {
        // Calculer pubkey
        let verifying_key = self.signing_key.verifying_key();
        let pubkey_bytes = verifying_key.as_bytes();
        let mut buf_pubkey_str = [0u8; 64];
        hex::encode_to_slice(pubkey_bytes, &mut buf_pubkey_str).unwrap();
        let pubkey_str = from_utf8(&buf_pubkey_str).unwrap();

        let message_id = self.generer_id(pubkey_str)?;
        let signature = self.signer(message_id.as_str())?;

        let message_ref: MessageMilleGrillesRef<C> = MessageMilleGrillesRef {
            id: message_id.as_str(),
            pubkey: pubkey_str,
            estampille: self.estampille,
            kind: self.kind,
            contenu: self.contenu,
            routage: self.routage,
            #[cfg(feature = "serde_json")]
            pre_migration: None,
            origine: self.origine,
            dechiffrage: self.dechiffrage,
            signature: signature.as_str(),
            certificat: self.certificat,
            millegrille: self.millegrille,
            #[cfg(feature = "serde_json")]
            attachements: None,
            contenu_valide: None,
        };

        // Ecrire dans buffer
        buffer.resize_default(buffer.capacity()).unwrap();
        let taille = match serde_json_core::to_slice(&message_ref, buffer) {
            Ok(taille) => taille,
            Err(e) => {
                error!("build_into Erreur serde_json_core::to_slice {:?}", e);
                Err("build_into:E1")?
            }
        };
        buffer.truncate(taille);  // S'assurer que le Vec a la taille utilisee
        debug!("Message serialise\n{:?}", from_utf8(buffer).unwrap());

        // Parse une nouvelle reference a partir du nouveau buffer
        // Permet de transferer l'ownership des references vers l'objet buffer
        Ok(MessageMilleGrillesRef::parse(from_utf8(buffer).unwrap()).unwrap())
    }

    fn generer_id(&self, pubkey: &str) -> Result<String<64>, &'static str> {
        // Extraire pubkey de la signing key
        let mut hacheur = HacheurMessage::new(pubkey, &self.estampille, self.kind.clone(), self.contenu);
        if let Some(routage) = self.routage.as_ref() {
            hacheur = hacheur.routage(routage);
        }
        hacheur.hacher()
    }

    fn signer(&self, id: &str) -> Result<String<128>, &'static str> {
        // Convertir id en bytes
        let mut id_bytes = [0u8; 32] as MessageId;
        if let Err(e) = hex::decode_to_slice(id, &mut id_bytes) {
            error!("Hex error sur id {} : {:?}", id, e);
            Err("signer:E1")?
        }

        let mut signature_buffer = [0u8; 128];
        let signature_str = signer_into(self.signing_key, &id_bytes, &mut signature_buffer);

        match String::from_str(signature_str) {
            Ok(inner) => Ok(inner),
            Err(()) => Err("signer:E2")?
        }
    }
}

#[cfg(test)]
mod messages_structs_tests {
    use super::*;
    use log::info;
    use crate::messages_structs::CONST_BUFFER_MESSAGE_MIN;

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
    fn test_build_into_u8() {
        let contenu = "Le contenu a inclure";
        let estampille = DateTime::from_timestamp(1710338722, 0).unwrap();
        let signing_key = SigningKey::from_bytes(b"01234567890123456789012345678901");
        let routage = RoutageMessage::for_action("Test", "test");
        let mut certificat: Vec<&str, CONST_NOMBRE_CERTIFICATS_MAX> = Vec::new();
        certificat.push("CERTIFICAT 1").unwrap();
        certificat.push("CERTIFICAT 2").unwrap();

        let generateur = MessageMilleGrillesBuilderDefault::new(
            MessageKind::Commande, contenu, estampille, &signing_key)
            .routage(routage)
            .certificat(certificat);

        let mut buffer: Vec<u8, CONST_BUFFER_MESSAGE_MIN> = Vec::new();
        let message = generateur.build_into(&mut buffer).unwrap();

        assert_eq!("6ac34b127bc0996f0ab09f3d6e91c14d65a2930689b3204eb9926a4ad4ee9078", message.id);
        assert_eq!("7bc3079518ed11da0336085bf6962920ff87fb3c4d630a9b58cb6153674f5dd6", message.pubkey);
        assert_eq!(estampille.timestamp(), message.estampille.timestamp());
    }

    #[cfg(feature = "alloc")]
    #[test_log::test]
    fn test_build_into_alloc() {
        let contenu = "Le contenu a inclure";
        let estampille = DateTime::from_timestamp(1710338722, 0).unwrap();
        let signing_key = SigningKey::from_bytes(b"01234567890123456789012345678901");
        let routage = RoutageMessage::for_action("Test", "test");
        let mut certificat: Vec<&str, CONST_NOMBRE_CERTIFICATS_MAX> = Vec::new();
        certificat.push("CERTIFICAT 1").unwrap();
        certificat.push("CERTIFICAT 2").unwrap();

        let generateur = MessageMilleGrillesBuilderDefault::new(
            MessageKind::Commande, contenu, estampille, &signing_key)
            .routage(routage)
            .certificat(certificat);

        let mut buffer: std::vec::Vec<u8> = std::vec::Vec::new();
        {
            let message_ref = generateur.build_into_alloc(&mut buffer).unwrap();
            assert_eq!("6ac34b127bc0996f0ab09f3d6e91c14d65a2930689b3204eb9926a4ad4ee9078", message_ref.id);
            assert_eq!("7bc3079518ed11da0336085bf6962920ff87fb3c4d630a9b58cb6153674f5dd6", message_ref.pubkey);
            assert_eq!(estampille.timestamp(), message_ref.estampille.timestamp());
        }
        debug!("test_build_into_vec Vec buffer :\n{}", from_utf8(buffer.as_slice()).unwrap());
        buffer.clear();
    }

}
