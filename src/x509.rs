use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::fs::read_to_string;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::Arc;

use chrono::{prelude::*, DateTime};
use log::debug;
use multibase::{Base, encode};
use multihash::Multihash;
use openssl::asn1::Asn1TimeRef;
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::x509::{X509, X509Ref, X509Req, X509ReqRef};
use x509_parser::parse_x509_certificate;
use blake2::{Blake2s256, Digest};
use ed25519_dalek::{SecretKey, SigningKey};
use openssl::stack::Stack;
use crate::error::Error;

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
pub fn charger_csr(pem: &str) -> Result<X509Req, ErrorStack> {
    X509Req::from_pem(pem.as_bytes())
}

pub fn csr_calculer_fingerprintpk(pem: &str) -> Result<String, Error> {
    let csr_parsed = X509Req::from_pem(pem.as_bytes())?;
    let cle_publique = csr_parsed.public_key()?.raw_public_key()?;
    Ok(hex::encode(cle_publique))
}

pub fn charger_chaine(pem: &str) -> Result<Vec<X509>, ErrorStack> {
    let stack = X509::stack_from_pem(pem.as_bytes());
    stack
}

pub fn calculer_fingerprint(cert: &X509) -> Result<String, Error> {
    // refact 2023.5.0 - le fingerprint (pubkey) correspond a la cle publique
    // note : risque de poisoning si cle privee est reutilisee dans plusieurs certificats
    let pk = cert.public_key()?;
    calculer_fingerprint_pk(&pk)
}

pub fn calculer_fingerprint_pk(pk: &PKey<Public>) -> Result<String, Error> {
    let cle_publique = match pk.raw_public_key() {
        Ok(inner) => inner,
        Err(e) => Err(e)?
    };
    let cle_hex = hex::encode(cle_publique);
    Ok(cle_hex)
}

pub fn calculer_idmg(cert: &X509) -> Result<String, Error> {
    calculer_idmg_ref(cert.deref())
}

pub fn calculer_idmg_ref(cert: &X509Ref) -> Result<String, Error> {
    let fingerprint = {
        let der = cert.to_der()?;
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
    let date_parsed = match EnveloppeCertificat::formatter_date_epoch(not_after) {
        Ok(inner) => inner,
        Err(e) => Err(Error::String(format!("Erreur parsing date expiration pour calculer_idmg : {:?}", e)))?
    };

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

    pub fn fingerprint(&self) -> Result<String, Error> {
        self.fingerprint_pk()
    }

    pub fn pubkey(&self) -> Result<Vec<u8>, Error> {
        let pk: PKey<Public> = self.certificat.public_key().unwrap();
        Ok(pk.raw_public_key()?)
    }

    pub fn not_valid_before(&self) -> Result<DateTime<Utc>, Error> {
        let not_before: &Asn1TimeRef = self.certificat.not_before();
        match EnveloppeCertificat::formatter_date_epoch(not_before) {
            Ok(date) => Ok(date),
            Err(e) => Err(Error::String(format!("Parsing erreur certificat not_valid_before : {:?}", e)))
        }
    }

    pub fn not_valid_after(&self) -> Result<DateTime<Utc>, Error> {
        let not_after: &Asn1TimeRef = self.certificat.not_after();
        match EnveloppeCertificat::formatter_date_epoch(not_after) {
            Ok(date) => Ok(date),
            Err(e) => Err(Error::String(format!("Parsing erreur certificat not_valid_after : {:?}", e)))
        }
    }

    pub fn idmg(&self) -> Result<String, Error> {
        let certificat = &self.certificat;
        let subject_name = certificat.subject_name();
        for entry in subject_name.entries_by_nid(Nid::ORGANIZATIONNAME) {
            let data = entry.data().as_slice().to_vec();
            return match String::from_utf8(data) {
                Ok(inner) => Ok(inner),
                Err(e) => Err(Error::String(format!("Erreur chargement IDMG : {:?}", e)))
            }
        }
        Err(Error::Str("IDMG non present sur certificat (OrganizationName)"))
    }

    /// Calcule le idmg pour ce certificat
    pub fn calculer_idmg(&self) -> Result<String, Error> {
        match self.idmg() {
            Ok(i) => Ok(i),
            Err(_) => calculer_idmg(&self.certificat)
        }
    }

    pub fn subject(&self) -> Result<HashMap<String, String>, Error> {
        let certificat = &self.certificat;
        let subject_name = certificat.subject_name();

        let mut resultat = HashMap::new();
        for entry in subject_name.entries() {
            let cle: &str = entry.object().nid().long_name()?;
            let data = entry.data().as_slice().to_vec();
            let valeur = String::from_utf8(data).expect("Erreur chargement IDMG");
            resultat.insert(cle.to_string(), valeur);
        }

        Ok(resultat)
    }

    pub fn get_common_name(&self) -> Result<String, Error> {
        let subject = self.subject()?;
        match subject.get("commonName") {
            Some(cn) => Ok(cn.to_owned()),
            None => Err(Error::Str("certificats.EnveloppeCertificat.get_common_name : commonName absent du subject"))
        }
    }

    pub fn issuer(&self) -> Result<HashMap<String, String>, Error> {
        let certificat = &self.certificat;
        let subject_name = certificat.issuer_name();

        let mut resultat = HashMap::new();
        for entry in subject_name.entries() {
            // debug!("Entry : {:?}", entry);
            let cle: &str = entry.object().nid().long_name()?;
            let data = entry.data().as_slice().to_vec();
            let valeur = String::from_utf8(data).expect("Erreur chargement IDMG");
            resultat.insert(cle.to_string(), valeur);
        }

        Ok(resultat)
    }

    pub fn est_ca(&self) -> Result<bool, Error> {
        let subject = self.subject()?;
        let issuer = self.issuer()?;
        Ok(subject == issuer)
    }

    pub fn formatter_date_epoch(date: &Asn1TimeRef) -> Result<DateTime<Utc>, Error> {
        let date_string = date.to_string();
        // debug!("formatter_date_epoch Date string : {}", date_string);
        if date_string.contains("GMT") {
            let date_parsed = NaiveDateTime::parse_from_str(
                date_string.as_str(), "%b %d %T %Y GMT")
                .map_err(|e| Error::String(format!("ParseError {:?}", e)))?
                .and_local_timezone(Utc).unwrap();
            Ok(date_parsed)
        } else {
            Err(Error::Str("Format de date non supporte - doit etre GMT"))?
        }
    }

    pub fn fingerprint_pk(&self) -> Result<String, Error> {
        let pk = self.certificat.public_key()?;
        calculer_fingerprint_pk(&pk)
    }

    pub fn publickey_bytes(&self) -> Result<String, Error> {
        let pk = self.certificat.public_key()?;
        let b = pk.raw_public_key()?;
        Ok(multibase::encode(Base::Base64, b))
    }

    pub fn extensions(&self) -> Result<ExtensionsMilleGrille, Error> {
        match self.certificat.to_der() {
            Ok(inner) => parse_x509(inner.as_slice()),
            Err(e) => Err(Error::String(format!("EnveloppeCertificat::extensions Erreur {:?}", e)))
        }
    }

    pub fn ca_pem(&self) -> Result<Option<String>, Error> {
        match &self.millegrille {
            Some(inner) => {
                let resultat = String::from_utf8(inner.to_pem()?)?;
                Ok(Some(resultat))
            },
            None => Ok(None)
        }
    }

    pub fn chaine_pem(&self) -> Result<Vec<String>, Error> {
        let mut vec = Vec::with_capacity(4);
        for c in &self.chaine {
            vec.push(String::from_utf8(c.to_pem()?)?);
        }
        Ok(vec)
    }

    pub fn intermediaire_stack(&self) -> Result<Stack<X509>, Error> {
        let mut intermediaire: Stack<X509> = match Stack::new() {
            Ok(inner) => inner,
            Err(e) => Err(Error::Openssl(e))?
        };

        // Generer chaine intermediaire - skip cert[0] (leaf)
        for cert in &self.chaine[1..] {
            if let Err(e) = intermediaire.push(cert.to_owned()) {
                Err(Error::Openssl(e))?
            }
        }

        Ok(intermediaire)
    }

    pub fn chaine_fingerprint_pem(&self) -> Result<Vec<FingerprintPem>, Error> {
        let mut vec = Vec::with_capacity(4);
        for c in &self.chaine {
            let fingerprint = calculer_fingerprint(c)?;
            let pem = String::from_utf8(c.to_pem()?)?;
            vec.push(FingerprintPem { fingerprint, pem, cert_millegrille: false } )
        }
        Ok(vec)
    }

    pub fn from_file(cert: &PathBuf) -> Result<Self, Error> {
        let chaine_pem_string = match read_to_string(cert) {
            Ok(inner) => inner,
            Err(e) => Err(Error::String(format!("EnveloppePrivee from_files Erreur read_to_string cert : {:?}", e)))?
        };
        Ok(EnveloppeCertificat::try_from(chaine_pem_string.as_str())?)
    }
}

impl TryFrom<&str> for EnveloppeCertificat {
    type Error = String;

    fn try_from<'a>(value: &str) -> Result<Self, Self::Error> {
        let pem = value.into();
        let chaine = match charger_chaine(pem) {
            Ok(inner) => inner,
            Err(e) => Err(format!("EnveloppeCertificat::try_from PEM invalide : {:?}", e))?
        };
        let certificat = match chaine.get(0) {
            Some(inner) => inner.to_owned(),
            None => Err(String::from("EnveloppeCertificat::try_from Erreur aucuns cerificats"))?
        };

        Ok(Self {certificat, chaine, millegrille: None})
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
    pub enveloppe_pub: Arc<EnveloppeCertificat>,
    pub enveloppe_ca: Arc<EnveloppeCertificat>,
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
        Self {
            enveloppe_pub: Arc::new(enveloppe_pub),
            enveloppe_ca: Arc::new(enveloppe_ca),
            cle_privee, chaine_pem, ca_pem, cle_privee_pem
        }
    }

    pub fn from_str<C,K,A>(cert: C, key: K, ca: A) -> Result<Self, Error>
        where C: AsRef<str>, K: ToString, A: ToString
    {
        let cert = cert.as_ref();
        let key = key.to_string();
        let ca = ca.to_string();

        let enveloppe_pub = match EnveloppeCertificat::try_from(cert) {
            Ok(inner) => inner,
            Err(e) => Err(Error::String(format!("EnveloppePrivee from_str Erreur try_from cert : {:?}", e)))?
        };
        let cle_privee: PKey<Private> = match PKey::private_key_from_pem(key.as_bytes()) {
            Ok(inner) => inner,
            Err(e) => Err(Error::String(format!("EnveloppePrivee from_str Erreur try_from cert : {:?}", e)))?
        };
        let enveloppe_ca = match EnveloppeCertificat::try_from(ca.as_str()) {
            Ok(inner) => inner,
            Err(e) => Err(Error::String(format!("EnveloppePrivee from_str Erreur try_from ca : {:?}", e)))?
        };

        let chaine_pem = enveloppe_pub.chaine_pem()?;
        let enveloppe = EnveloppePrivee {
            enveloppe_pub: Arc::new(enveloppe_pub),
            enveloppe_ca: Arc::new(enveloppe_ca),
            cle_privee, chaine_pem, ca_pem: ca, cle_privee_pem: key
        };

        // Verifier que le CA, cert et cle privee correspondent. Lance une Err au besoin.
        enveloppe.verifier_correspondance()?;

        Ok(enveloppe)
    }

    pub fn from_files(cert: &PathBuf, key: &PathBuf, ca: &PathBuf) -> Result<Self, Error> {
        let chaine_pem_string = match read_to_string(cert) {
            Ok(inner) => inner,
            Err(e) => Err(Error::String(format!("EnveloppePrivee from_files Erreur read_to_string cert : {:?}", e)))?
        };
        let cle_privee_pem = match read_to_string(key) {
            Ok(inner) => inner,
            Err(e) => Err(Error::String(format!("EnveloppePrivee from_files Erreur read_to_string key : {:?}", e)))?
        };
        let ca_pem = match read_to_string(ca) {
            Ok(inner) => inner,
            Err(e) => Err(Error::String(format!("EnveloppePrivee from_files Erreur read_to_string ca : {:?}", e)))?
        };
        EnveloppePrivee::from_str(chaine_pem_string, cle_privee_pem, ca_pem)
    }

    fn verifier_correspondance(&self) -> Result<(), Error> {
        // Verifier que la cle privee correspond au certificat (pubkey)
        let pubkey_vec = self.enveloppe_pub.pubkey()?;
        let private_pubkey_vec = match self.cle_privee.raw_public_key() {
            Ok(inner) => inner,
            Err(e) => Err(Error::String(format!("EnveloppeCertificat::verifier_correspondance Erreur cle privee -> public_key() {:?}", e)))?
        };

        debug!("Cle publiques cert et privkey vec\n{:?}\n{:?}", pubkey_vec, private_pubkey_vec);

        if pubkey_vec.as_slice() != private_pubkey_vec.as_slice() {
            Err(Error::Str("EnveloppeCertificat::verifier_correspondance Mismatch cle publique/privee"))?
        }

        // Verifier que le CA correspond au certificat
        let idmg_cert = self.enveloppe_pub.idmg()?;
        let idmg_ca = self.enveloppe_ca.calculer_idmg()?;
        if idmg_cert != idmg_ca {
            Err(Error::Str("Mismatch CA et cert (idmg)"))?
        }

        if ! self.enveloppe_ca.est_ca()? {
            Err(Error::Str("Certificat CA n'est pas self-signed"))?
        }

        Ok(())
    }

    pub fn fingerprint(&self) -> Result<String, Error> {
        let pk = self.enveloppe_pub.certificat.public_key()?;
        Ok(calculer_fingerprint_pk(&pk)?)
    }

}

impl Debug for EnveloppePrivee {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let fingerprint = self.fingerprint().unwrap_or_else(|_| String::from("N/A"));
        f.write_str(format!("Enveloppe privee {}", fingerprint).as_str())
    }
}

impl TryInto<SigningKey> for &EnveloppePrivee {

    type Error = Error;

    fn try_into<'a>(self) -> Result<SigningKey, Self::Error> {
        let mut cle_privee_u8 = SecretKey::default();
        match self.cle_privee.raw_private_key() {
            Ok(inner) => cle_privee_u8.copy_from_slice(inner.as_slice()),
            Err(e) => Err(Error::String(format!("TryInto<SigningKey> for &EnveloppePrivee Erreur raw_private_key {:?}", e)))?
        };
        Ok(SigningKey::from_bytes(&cle_privee_u8))
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

fn parse_x509(cert: &[u8]) -> Result<ExtensionsMilleGrille, Error> {
    let (_, cert_parsed) = match parse_x509_certificate(&cert) {
        Ok(inner) => inner,
        Err(e) => Err(format!("Erreur parsing X509 : {:?}", e))?
    };
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
    pub exchanges: Option<Vec<String>>,
    pub roles: Option<Vec<String>>,
    pub domaines: Option<Vec<String>>,
    pub user_id: Option<String>,
    pub delegation_globale: Option<String>,
    pub delegation_domaines: Option<Vec<String>>,
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

impl TryFrom<X509Ref> for ExtensionsMilleGrille {
    type Error = Error;

    fn try_from(value: X509Ref) -> Result<Self, Self::Error> {
        let cert_der = match value.to_der() {
            Ok(inner) => inner,
            Err(e) => Err(format!("TryFrom<X509Ref> Erreur {:?}", e))?
        };
        parse_x509(&cert_der)
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

#[derive(Clone, Debug)]
pub struct FingerprintPem {
    pub fingerprint: String,

    /// Chaine PEM du certificat
    pub pem: String,

    /// True si le pem represente le certificat de MilleGrille
    pub cert_millegrille: bool,
}

#[cfg(test)]
pub mod messages_structs_tests {
    use super::*;
    use log::info;

    pub const CERT_1: &str = r#"-----BEGIN CERTIFICATE-----
MIIClDCCAkagAwIBAgIUQuFP9EOrsQuFkWnXEH8UQNZ1EN4wBQYDK2VwMHIxLTAr
BgNVBAMTJGY4NjFhYWZkLTUyOTctNDA2Zi04NjE3LWY3Yjg4MDlkZDQ0ODFBMD8G
A1UEChM4emVZbmNScUVxWjZlVEVtVVo4d2hKRnVIRzc5NmVTdkNUV0U0TTQzMml6
WHJwMjJiQXR3R203SmYwHhcNMjQwMjIwMTE0NjUzWhcNMjQwMzIyMTE0NzEzWjCB
gTEtMCsGA1UEAwwkZjg2MWFhZmQtNTI5Ny00MDZmLTg2MTctZjdiODgwOWRkNDQ4
MQ0wCwYDVQQLDARjb3JlMUEwPwYDVQQKDDh6ZVluY1JxRXFaNmVURW1VWjh3aEpG
dUhHNzk2ZVN2Q1RXRTRNNDMyaXpYcnAyMmJBdHdHbTdKZjAqMAUGAytlcAMhANHZ
whRt4OWZcSSUidlxR4BQ1VvJE93uugvzxg3Vss0xo4HdMIHaMCsGBCoDBAAEIzQu
c2VjdXJlLDMucHJvdGVnZSwyLnByaXZlLDEucHVibGljMAwGBCoDBAEEBGNvcmUw
TAYEKgMEAgREQ29yZUJhY2t1cCxDb3JlQ2F0YWxvZ3VlcyxDb3JlTWFpdHJlRGVz
Q29tcHRlcyxDb3JlUGtpLENvcmVUb3BvbG9naWUwDwYDVR0RBAgwBoIEY29yZTAf
BgNVHSMEGDAWgBRQUbOqbsQcXmnk3+moqmk1PXOGKjAdBgNVHQ4EFgQU4+j+8rBR
K+WeiFzo6EIR+t0C7o8wBQYDK2VwA0EAab2vFykbUk1cWugRd10rGiTKp/PKZdG5
X+Y+lrHe8AHcrpGGtUV8mwwcDsRbw2wtRq2ENceNlQAcwblEkxLvCA==
-----END CERTIFICATE-----
"#;

    pub const CERT_INTER: &str = r#"-----BEGIN CERTIFICATE-----
MIIBozCCAVWgAwIBAgIKAnY5ZhNJUlVzaTAFBgMrZXAwFjEUMBIGA1UEAxMLTWls
bGVHcmlsbGUwHhcNMjQwMTMwMTM1NDU3WhcNMjUwODEwMTM1NDU3WjByMS0wKwYD
VQQDEyRmODYxYWFmZC01Mjk3LTQwNmYtODYxNy1mN2I4ODA5ZGQ0NDgxQTA/BgNV
BAoTOHplWW5jUnFFcVo2ZVRFbVVaOHdoSkZ1SEc3OTZlU3ZDVFdFNE00MzJpelhy
cDIyYkF0d0dtN0pmMCowBQYDK2VwAyEAPUMU7tlz3HCEB+VzG8NVFQ/nFKjIOZmV
egt+ub3/7SajYzBhMBIGA1UdEwEB/wQIMAYBAf8CAQAwCwYDVR0PBAQDAgEGMB0G
A1UdDgQWBBRQUbOqbsQcXmnk3+moqmk1PXOGKjAfBgNVHSMEGDAWgBTTiP/MFw4D
DwXqQ/J2LLYPRUkkETAFBgMrZXADQQB6S4tids+r9e5d+mwpdkrAE2k3+8H0x65z
WD5eP7A2XeEr0LbxRPNyaO+Q8fvnjjCKasn97MTPSCXnU/4JbWYK
-----END CERTIFICATE-----
"#;

    pub const CERT_CA: &str = r#"-----BEGIN CERTIFICATE-----
MIIBQzCB9qADAgECAgoHBykXJoaCCWAAMAUGAytlcDAWMRQwEgYDVQQDEwtNaWxs
ZUdyaWxsZTAeFw0yMjAxMTMyMjQ3NDBaFw00MjAxMTMyMjQ3NDBaMBYxFDASBgNV
BAMTC01pbGxlR3JpbGxlMCowBQYDK2VwAyEAnnixameVCZAzfx4dO+L63DOk/34I
/TC4fIA1Rxn19+KjYDBeMA8GA1UdEwEB/wQFMAMBAf8wCwYDVR0PBAQDAgLkMB0G
A1UdDgQWBBTTiP/MFw4DDwXqQ/J2LLYPRUkkETAfBgNVHSMEGDAWgBTTiP/MFw4D
DwXqQ/J2LLYPRUkkETAFBgMrZXADQQBSb0vXhw3pw25qrWoMjqROjawe7/kMlu7p
MJyb/Ppa2C6PraSVPgJGWKl+/5S5tBr58KFNg+0H94CH4d1VCPwI
-----END CERTIFICATE-----
"#;

    #[test_log::test]
    fn test_try_from_str_1cert() {
        let cert = EnveloppeCertificat::try_from(CERT_1).unwrap();
        info!("Certificat charge OK : {}", cert.fingerprint().unwrap());
        assert_eq!("d1d9c2146de0e59971249489d971478050d55bc913ddeeba0bf3c60dd5b2cd31", cert.fingerprint().unwrap());
        assert_eq!(1, cert.chaine.len());
        assert_eq!("f861aafd-5297-406f-8617-f7b8809dd448", cert.get_common_name().unwrap());
        let subject = cert.subject().unwrap();
        info!("Subject : {:?}", subject);
        assert_eq!("core", subject.get("organizationalUnitName").unwrap());
        let idmg = cert.idmg().unwrap();
        assert_eq!("zeYncRqEqZ6eTEmUZ8whJFuHG796eSvCTWE4M432izXrp22bAtwGm7Jf", idmg.as_str());
    }

    #[test_log::test]
    fn test_try_from_str_chaine() {
        let chaine = vec![CERT_1, CERT_INTER].join("\n");
        let cert = EnveloppeCertificat::try_from(chaine.as_str()).unwrap();
        info!("Certificat charge OK : {}", cert.fingerprint().unwrap());
        assert_eq!("d1d9c2146de0e59971249489d971478050d55bc913ddeeba0bf3c60dd5b2cd31", cert.fingerprint().unwrap());
        assert_eq!(2, cert.chaine.len());
    }

    #[test_log::test]
    fn test_extensions() {
        let cert = EnveloppeCertificat::try_from(CERT_1).unwrap();
        let extensions = cert.extensions().unwrap();
        info!("Extensions : {:?}", extensions);
        let roles = extensions.roles.unwrap();
        assert_eq!("core", roles.get(0).unwrap());
        let securite = extensions.exchanges.unwrap();
        assert_eq!(4, securite.len());
        assert_eq!("4.secure", securite.get(0).unwrap());
    }

    #[test_log::test]
    fn test_idmg() {
        let cert = EnveloppeCertificat::try_from(CERT_CA).unwrap();
        let idmg = cert.calculer_idmg().unwrap();
        assert_eq!("zeYncRqEqZ6eTEmUZ8whJFuHG796eSvCTWE4M432izXrp22bAtwGm7Jf", idmg.as_str());
        assert!(cert.est_ca().unwrap());
    }

    #[test_log::test]
    fn test_enveloppe_privee() {
        let path_cert = PathBuf::from("/var/opt/millegrilles/secrets/pki.core.cert");
        let path_key = PathBuf::from("/var/opt/millegrilles/secrets/pki.core.cle");
        let path_ca = PathBuf::from("/var/opt/millegrilles/configuration/pki.millegrille.cert");

        // Charger enveloppe. Verifie automatiquement la correspondance.
        assert!(EnveloppePrivee::from_files(&path_cert, &path_key, &path_ca).is_ok());
    }

    #[test_log::test]
    fn test_enveloppe_privee_mismatch_cert() {
        let path_cert_mauvais = PathBuf::from("/var/opt/millegrilles/secrets/pki.instance.cert");
        let path_key = PathBuf::from("/var/opt/millegrilles/secrets/pki.core.cle");
        let path_ca = PathBuf::from("/var/opt/millegrilles/configuration/pki.millegrille.cert");

        // Charger enveloppe. Verifie automatiquement la correspondance.
        assert!(EnveloppePrivee::from_files(&path_cert_mauvais, &path_key, &path_ca).is_err());
    }

}
