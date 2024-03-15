use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Debug, Formatter};
use std::ops::Deref;
use std::sync::Arc;
use std::time::Instant;

use chrono::{prelude::*, format::ParseError, DateTime};
use log::{debug, warn};
use multibase::{Base, encode};
use multihash::Multihash;
use openssl::asn1::Asn1TimeRef;
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::stack::{Stack, StackRef};
use openssl::x509::{X509, X509Ref, X509Req, X509ReqRef, X509StoreContext};
use openssl::x509::store::X509Store;
use x509_parser::parse_x509_certificate;
use blake2::{Blake2s256, Digest};

use crate::hachages::HachageCode;
use crate::securite::Securite;

// OID des extensions x509v3 de MilleGrille
const OID_EXCHANGES: &str = "1.2.3.4.0";
const OID_ROLES: &str = "1.2.3.4.1";
const OID_DOMAINES: &str = "1.2.3.4.2";
const OID_USERID: &str = "1.2.3.4.3";
const OID_DELEGATION_GLOBALE: &str = "1.2.3.4.4";
const OID_DELEGATION_DOMAINES: &str = "1.2.3.4.5";

#[inline]
pub fn charger_certificat(pem: &str) -> Result<X509, ErrorStack> {
    X509::from_pem(pem.as_bytes())
}

#[inline]
pub fn charger_csr(pem: &str) -> Result<X509Req, ErrorStack> {
    X509Req::from_pem(pem.as_bytes())
}

pub fn csr_calculer_fingerprintpk(pem: &str) -> Result<String, ErrorStack> {
    let csr_parsed = X509Req::from_pem(pem.as_bytes())?;
    let cle_publique = csr_parsed.public_key()?.raw_public_key()?;
    Ok(hex::encode(cle_publique))
}

pub fn charger_chaine(pem: &str) -> Result<Vec<X509>, ErrorStack> {
    let stack = X509::stack_from_pem(pem.as_bytes());
    stack
}

pub fn calculer_fingerprint(cert: &X509) -> Result<String, ErrorStack> {
    // refact 2023.5.0 - le fingerprint (pubkey) correspond a la cle publique
    // note : risque de poisoning si cle privee est reutilisee dans plusieurs certificats
    match cert.public_key() {
        Ok(inner) => calculer_fingerprint_pk(&inner),
        Err(e) => Err(e)
    }
}

pub fn calculer_fingerprint_pk(pk: &PKey<Public>) -> Result<String, ErrorStack> {
    let cle_publique = match pk.raw_public_key() {
        Ok(inner) => inner,
        Err(e) => Err(e)?
    };
    let cle_hex = hex::encode(cle_publique);
    Ok(cle_hex)
}

pub fn calculer_idmg(cert: &X509) -> Result<String, String> {
    calculer_idmg_ref(cert.deref())
}

pub fn calculer_idmg_ref(cert: &X509Ref) -> Result<String, String> {
    let fingerprint = {
        let der = match cert.to_der() {
            Ok(v) => v,
            Err(e) => Err(format!("calculer_idmg_ref fingerprint error : {:?}", e))?
        };
        let mut hasher = Blake2s256::new();
        hasher.update(der);
        hasher.finalize()
    };

    // Multihash
    let mh: Multihash<32> = Multihash::wrap(HachageCode::Blake2s256 as u64, fingerprint.as_ref()).unwrap();
    let mh_bytes: Vec<u8> = mh.to_bytes();

    // Preparation slice du IDMG, 41 bytes
    let mut idmg_slice: [u8; 41] = [0; 41];

    // Version
    idmg_slice[0] = 0x2;

    // SHA-256
    idmg_slice[5..41].clone_from_slice(mh_bytes.as_slice());

    // Date expiration ( ceil(epoch sec/1000) )
    let not_after: &Asn1TimeRef = cert.not_after();
    let date_parsed = EnveloppeCertificat::formatter_date_epoch(not_after).expect("Erreur parsing date expiration pour calculer_idmg");

    // Calculer expiration avec ceil(epoch / 1000), permet de reduire la date a u32.
    let epoch_ts: f64 = date_parsed.timestamp() as f64;
    let epoch_ts: u32 = (epoch_ts / 1000.0).ceil() as u32;

    idmg_slice[1..5].clone_from_slice(&epoch_ts.to_le_bytes());

    let val: String = encode(Base::Base58Btc, idmg_slice);

    Ok(val)
}

#[derive(Clone)]
pub struct EnveloppeCertificat {
    pub certificat: X509,
    pub chaine: Vec<X509>,
    pub millegrille: Option<X509>,
}

impl EnveloppeCertificat {

    pub fn fingerprint(&self) -> Result<String, ErrorStack> {
        self.fingerprint_pk()
    }

    pub fn not_valid_before(&self) -> Result<DateTime<Utc>, String> {
        let not_before: &Asn1TimeRef = self.certificat.not_before();
        match EnveloppeCertificat::formatter_date_epoch(not_before) {
            Ok(date) => Ok(date),
            Err(e) => Err(format!("Parsing erreur certificat not_valid_before : {:?}", e))
        }
    }

    pub fn not_valid_after(&self) -> Result<DateTime<Utc>, String> {
        let not_after: &Asn1TimeRef = self.certificat.not_after();
        match EnveloppeCertificat::formatter_date_epoch(not_after) {
            Ok(date) => Ok(date),
            Err(e) => Err(format!("Parsing erreur certificat not_valid_after : {:?}", e))
        }
    }

    pub fn idmg(&self) -> Result<String, String> {
        let certificat = &self.certificat;
        let subject_name = certificat.subject_name();
        for entry in subject_name.entries_by_nid(Nid::ORGANIZATIONNAME) {
            let data = entry.data().as_slice().to_vec();
            return Ok(String::from_utf8(data).expect("Erreur chargement IDMG"))
        }
        Err("IDMG non present sur certificat (OrganizationName)".into())
    }

    /// Calcule le idmg pour ce certificat
    pub fn calculer_idmg(&self) -> Result<String, String> {
        match self.idmg() {
            Ok(i) => Ok(i),
            Err(_) => calculer_idmg(&self.certificat)
        }
    }

    pub fn subject(&self) -> Result<HashMap<String, String>, String> {
        let certificat = &self.certificat;
        let subject_name = certificat.subject_name();

        let mut resultat = HashMap::new();
        for entry in subject_name.entries() {
            // debug!("Entry : {:?}", entry);
            let cle: String = entry.object().nid().long_name().expect("Erreur chargement Nid de subject").into();
            let data = entry.data().as_slice().to_vec();
            let valeur = String::from_utf8(data).expect("Erreur chargement IDMG");
            resultat.insert(cle, valeur);
        }

        Ok(resultat)
    }

    pub fn get_common_name(&self) -> Result<String, String> {
        let subject = self.subject()?;
        match subject.get("commonName") {
            Some(cn) => Ok(cn.to_owned()),
            None => Err("certificats.EnveloppeCertificat.get_common_name : commonName absent du subject".into())
        }
    }

    pub fn issuer(&self) -> Result<HashMap<String, String>, String> {
        let certificat = &self.certificat;
        let subject_name = certificat.issuer_name();

        let mut resultat = HashMap::new();
        for entry in subject_name.entries() {
            // debug!("Entry : {:?}", entry);
            let cle: String = entry.object().nid().long_name().expect("Erreur chargement Nid de subject").into();
            let data = entry.data().as_slice().to_vec();
            let valeur = String::from_utf8(data).expect("Erreur chargement IDMG");
            resultat.insert(cle, valeur);
        }

        Ok(resultat)
    }

    pub fn est_ca(&self) -> Result<bool, String> {
        let subject = self.subject()?;
        let issuer = self.issuer()?;

        Ok(subject == issuer)
    }

    pub fn formatter_date_epoch(date: &Asn1TimeRef) -> Result<DateTime<Utc>, ParseError> {
        let str_date = date.to_string();
        match DateTime::parse_from_str(&str_date, "%b %d %T %Y %Z") {
            Ok(inner) => Ok(inner.to_utc()),
            Err(e) => Err(e)
        }
    }

    pub fn fingerprint_pk(&self) -> Result<String, ErrorStack> {
        let pk = self.certificat.public_key()?;
        calculer_fingerprint_pk(&pk)
    }

    pub fn publickey_bytes(&self) -> Result<String, String> {
        let pk = match self.certificat.public_key() {
            Ok(pk) => pk,
            Err(e) => Err(format!("certificat.public_bytes Erreur public_key() {:?}", e))?
        };
        match pk.raw_public_key() {
            Ok(b) => Ok(multibase::encode(Base::Base64, b)),
            Err(e) => Err(format!("certificat.public_bytes Erreur raw_private_key() {:?}", e))?
        }
    }

}

impl Debug for EnveloppeCertificat {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.fingerprint_pk() {
            Ok(inner) => write!(f, "Certificat pk:{}", inner),
            Err(_) => write!(f, "Enveloppe certificat (no fingerprint)")
        }
    }
}

/// Enveloppe avec cle pour cle et certificat combine
#[derive(Clone)]
pub struct EnveloppePrivee {
    pub enveloppe_pub: EnveloppeCertificat,
    pub enveloppe_ca: EnveloppeCertificat,
    pub cle_privee: PKey<Private>,
    pub chaine_pem: Vec<String>,
    pub ca_pem: String,
    pub cle_privee_pem: String,
}

impl EnveloppePrivee {

    pub fn new(
        enveloppe_pub: EnveloppeCertificat,
        enveloppe_ca: EnveloppeCertificat,
        cle_privee: PKey<Private>,
        chaine_pem: Vec<String>,
        ca_pem: String,
        cle_privee_pem: String,
    ) -> Self {
        Self { enveloppe_pub, enveloppe_ca, cle_privee, chaine_pem, ca_pem, cle_privee_pem }
    }

    pub fn fingerprint(&self) -> Result<String, ErrorStack> {
        let pk = self.enveloppe_pub.certificat.public_key()?;
        calculer_fingerprint_pk(&pk)
    }

}

impl Debug for EnveloppePrivee {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("Enveloppe privee {}", self.fingerprint()?).as_str())
    }
}

/// Parse et retourne une map avec le subject du CSR
pub fn get_csr_subject(csr: &X509ReqRef) -> Result<HashMap<String, String>, String> {
    let subject_name = csr.subject_name();

    let mut resultat = HashMap::new();
    for entry in subject_name.entries() {
        let cle: String = entry.object().nid().long_name().expect("Erreur chargement Nid de subject").into();
        let data = entry.data().as_slice().to_vec();
        let valeur = String::from_utf8(data).expect("Erreur chargement IDMG");
        resultat.insert(cle, valeur);
    }

    Ok(resultat)
}

fn parse_x509(cert: &[u8]) -> Result<ExtensionsMilleGrille, String> {
    let (_, cert_parsed) = parse_x509_certificate(&cert).expect("Erreur parsing X509");
    debug!("Certificat X509 parsed : {:?}", cert_parsed);

    let extensions = cert_parsed.extensions();

    let mut exchanges = None;
    let mut roles = None;
    let mut domaines = None;
    let mut user_id = None;
    let mut delegation_globale = None;
    let mut delegation_domaines = None;

    for ext in extensions {
        debug!("Extension ext = {:?}", ext);
        match ext.oid.to_id_string().as_str() {
            OID_EXCHANGES => { exchanges = Some(extraire_vec_strings(ext.value).expect("Erreur extraction exchanges")) },
            OID_ROLES => { roles = Some(extraire_vec_strings(ext.value).expect("Erreur extraction roles")) },
            OID_DOMAINES => { domaines = Some(extraire_vec_strings(ext.value).expect("Erreur extraction domaines")) },
            OID_USERID => { user_id = Some(String::from_utf8(ext.value.to_vec()).expect("Erreur extraction user_id")) },
            OID_DELEGATION_GLOBALE => { delegation_globale = Some(String::from_utf8(ext.value.to_vec()).expect("Erreur extraction delegation_globale")) },
            OID_DELEGATION_DOMAINES => { delegation_domaines = Some(extraire_vec_strings(ext.value).expect("Erreur extraction delegation_domaines")) },
            _ => (), // Inconnu
        }
    }

    Ok(ExtensionsMilleGrille {exchanges, roles, domaines, user_id, delegation_globale, delegation_domaines})
}

#[derive(Clone, Debug)]
pub struct ExtensionsMilleGrille {
    exchanges: Option<Vec<String>>,
    roles: Option<Vec<String>>,
    domaines: Option<Vec<String>>,
    pub user_id: Option<String>,
    delegation_globale: Option<String>,
    delegation_domaines: Option<Vec<String>>,
}

impl ExtensionsMilleGrille {
    /// Retourne le plus haut niveau de securite (echange) supporte par ce certificat
    pub fn exchange_top(&self) -> Result<Option<Securite>, &'static str> {
        match self.exchanges.as_ref() {
            Some(e) => {
                let mut sec = Securite::L1Public;
                for s in e {
                    if let Ok(inner_sec) = Securite::try_from(s.as_str()) {
                        let rk_courant = sec.clone() as isize;
                        let rk_inner = inner_sec.clone() as isize;
                        if rk_courant < rk_inner {
                            sec = inner_sec;
                        }
                    }
                }

                Ok(Some(sec))
            },
            None => Ok(None),
        }
    }
}

fn extraire_vec_strings(data: &[u8]) -> Result<Vec<String>, String> {
    let value= String::from_utf8(data.to_vec()).expect("Erreur lecture exchanges");
    let split = value.split(",");
    let mut vec = Vec::new();
    for v in split {
        vec.push(String::from(v));
    }

    Ok(vec)
}
