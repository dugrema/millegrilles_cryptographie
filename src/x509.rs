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

pub fn charger_enveloppe(pem: &str, store: Option<&X509Store>, ca_pem: Option<&str>)
    -> Result<EnveloppeCertificat, ErrorStack>
{
    let chaine_x509 = charger_chaine(pem)?;

    let millegrille = match ca_pem {
        Some(c) => X509::stack_from_pem(c.as_bytes())?.pop(),
        None => None
    };

    // Calculer fingerprint du certificat
    let cert: &X509 = chaine_x509.get(0).unwrap();
    let fingerprint = calculer_fingerprint(cert).expect("fingerprint");

    // Pousser les certificats intermediaires (pas le .0, ni le dernier)
    let mut intermediaire: Stack<X509> = Stack::new()?;
    for cert_idx in 1..chaine_x509.len() {
        let _ = intermediaire.push(chaine_x509.get(cert_idx).expect("charger_enveloppe intermediaire").to_owned());
    }

    // Verifier la chaine avec la date courante.
    let mut presentement_valide = false;
    match store {
        Some(s) => {
            presentement_valide = verifier_certificat(cert, &intermediaire, s)?;
        },
        None => (),
    }

    let cle_publique = cert.public_key().unwrap();

    let cert_der = cert.to_der().expect("Erreur exporter cert format DEV");
    let extensions = parse_x509(cert_der.as_slice()).expect("Erreur preparation extensions X509 MilleGrille");

    Ok(EnveloppeCertificat {
        certificat: cert.clone(),
        chaine: chaine_x509,
        cle_publique,
        intermediaire,
        millegrille,
        presentement_valide,
        fingerprint,
        date_enveloppe: Instant::now(),
        extensions_millegrille: extensions,
    })
}

pub fn verifier_certificat(cert: &X509, chaine_pem: &StackRef<X509>, store: &X509Store) -> Result<bool, ErrorStack> {
    let mut store_context = X509StoreContext::new()?;
    store_context.init(store, cert, chaine_pem, |c| {
        let mut resultat = c.verify_cert()?;

        if resultat == true {
            // Verifier que l'organisation du certificat correspond au idmg du CA
            let organization = match cert.subject_name().entries_by_nid(Nid::ORGANIZATIONNAME).next() {
                Some(o) => {
                    let data = o.data().as_slice().to_vec();
                    match String::from_utf8(data) {
                        Ok(o) => Some(o),
                        Err(_) => None,
                    }
                },
                None => None,
            };

            if let Some(organization) = organization {
                // Verifier le idmg
                match c.chain() {
                    Some(s) => {
                        match s.iter().last() {
                            Some(ca) => {
                                match calculer_idmg_ref(ca) {
                                    Ok(idmg_ca) => {
                                        debug!("Sujet organization cert : {}, idmg cert CA {} trouve durant validation : {:?}", organization, idmg_ca, ca.subject_name());
                                        resultat = idmg_ca == organization;
                                    },
                                    Err(e) => {
                                        warn!("Erreur calcul idmg CA : {:?}", e);
                                        resultat = false;
                                    }
                                };
                            },
                            None => {
                                warn!("Cert CA absent, verification false");
                                resultat = false;
                            }
                        }
                    },
                    None => {
                        warn!("La chaine n'a pas ete produite suite a la validation, verif idmg impossible");
                        resultat = false;
                    },
                };
            } else {
                warn!("Organization manquante du certificat, on le considere invalide");
                resultat = false;
            }
        } else {
            debug!("Certificat store considere le certificat invalide");
        }

        Ok(resultat)
    })
}

pub fn calculer_fingerprint(cert: &X509) -> Result<String, String> {
    // refact 2023.5.0 - le fingerprint (pubkey) correspond a la cle publique
    // note : risque de poisoning si cle privee est reutilisee dans plusieurs certificats
    match cert.public_key() {
        Ok(inner) => calculer_fingerprint_pk(&inner),
        Err(e) => Err(format!("certificats.calculer_fingerprint Erreur public_key() {:?}", e))?
    }
}

pub fn calculer_fingerprint_pk(pk: &PKey<Public>) -> Result<String, String> {
    let cle_publique = match pk.raw_public_key() {
        Ok(inner) => inner,
        Err(e) => Err(format!("certificats.calculer_fingerprint_pk Erreur raw_public_key() {:?}", e))?
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

pub struct EnveloppeCertificat {
    certificat: X509,
    chaine: Vec<X509>,
    pub cle_publique: PKey<Public>,
    intermediaire: Stack<X509>,
    millegrille: Option<X509>,
    pub presentement_valide: bool,
    pub fingerprint: String,
    date_enveloppe: Instant,
    extensions_millegrille: ExtensionsMilleGrille,
}

impl EnveloppeCertificat {

    /// Retourne le certificat de l'enveloppe.
    pub fn certificat(&self) -> &X509 { &self.certificat }

    pub fn presentement_valide(&self) -> bool { self.presentement_valide }

    pub fn fingerprint(&self) -> &String { &self.fingerprint }

    pub fn get_pem_vec(&self) -> Vec<FingerprintCert> {
        let mut vec = Vec::new();
        for c in &self.chaine {
            let p = String::from_utf8(c.to_pem().unwrap()).unwrap();
            let fp = calculer_fingerprint(c).unwrap();
            vec.push(FingerprintCert{fingerprint: fp, pem: p});
        }
        vec
    }

    /// Extrait les pems et retourne dans un Vec<String>
    pub fn get_pem_vec_extracted(&self) -> Vec<String> {
        self.get_pem_vec().iter().map(|p| p.pem.clone()).collect()
    }

    pub fn get_pem_ca(&self) -> Result<Option<String>,String> {
        match &self.millegrille {
            Some(c) => match c.to_pem() {
                Ok(c) => match String::from_utf8(c) {
                    Ok(c) => Ok(Some(c)),
                    Err(e) => Err(format!("certificats.get_pem_ca Erreur conversion pem CA : {:?}", e))
                },
                Err(e) => Err(format!("certificats.get_pem_ca Erreur conversion pem CA : {:?}", e))
            },
            None => Ok(None)
        }
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

    pub fn fingerprint_pk(&self) -> Result<String, String> {
        let pk = self.certificat.public_key().expect("Erreur extraction cle publique pour fingerprint_pk");
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

    pub fn publickey_bytes_encoding(&self, base: Base, strip: bool) -> Result<String, String> {
        let pk = match self.certificat.public_key() {
            Ok(pk) => pk,
            Err(e) => Err(format!("certificat.public_bytes Erreur public_key() {:?}", e))?
        };
        match pk.raw_public_key() {
            Ok(b) => {
                let encoded_string: String = multibase::encode(base, b);
                match strip {
                    true => {
                        let encoded_remove_id = &encoded_string[1..];
                        Ok(encoded_remove_id.to_string())
                    },
                    false => Ok(encoded_string)
                }
            },
            Err(e) => Err(format!("certificat.public_bytes Erreur raw_private_key() {:?}", e))?
        }
    }

    /// Retourne la cle publique pour le certificat (leaf) et le CA (millegrille)
    /// Utilise pour chiffrage de cles secretes
    pub fn fingerprint_cert_publickeys(&self) -> Result<Vec<FingerprintCertPublicKey>, Box<dyn Error>> {
        let cert_leaf = self.chaine.get(0).expect("leaf");
        let fp_leaf = calculer_fingerprint(cert_leaf)?;
        let fpleaf = FingerprintCertPublicKey { fingerprint: fp_leaf, public_key: cert_leaf.public_key()?, est_cle_millegrille: false };

        let cert_mg = self.chaine.last().expect("cert inter");
        let fp_mg = calculer_fingerprint(cert_mg)?;
        let fpmg = FingerprintCertPublicKey { fingerprint: fp_mg, public_key: cert_mg.public_key()?, est_cle_millegrille: false };

        Ok(vec!(fpleaf, fpmg))
    }

    pub fn get_exchanges(&self) -> Result<&Option<Vec<String>>, String> { Ok(&self.extensions_millegrille.exchanges) }
    pub fn get_roles(&self) -> Result<&Option<Vec<String>>, String> { Ok(&self.extensions_millegrille.roles) }
    pub fn get_domaines(&self) -> Result<&Option<Vec<String>>, String> { Ok(&self.extensions_millegrille.domaines) }
    pub fn get_user_id(&self) -> Result<&Option<String>, String> { Ok(&self.extensions_millegrille.user_id) }
    pub fn get_delegation_globale(&self) -> Result<&Option<String>, String> { Ok(&self.extensions_millegrille.delegation_globale) }
    pub fn get_delegation_domaines(&self) -> Result<&Option<Vec<String>>, String> { Ok(&self.extensions_millegrille.delegation_domaines) }

}

impl Clone for EnveloppeCertificat {

    fn clone(&self) -> Self {

        let mut intermediaire: Stack<X509> = Stack::new().expect("stack");
        for cert in &self.intermediaire {
            intermediaire.push(cert.to_owned()).expect("push");
        }

        EnveloppeCertificat {
            certificat: self.certificat.clone(),
            chaine: self.chaine.clone(),
            cle_publique: self.cle_publique.clone(),
            intermediaire,
            millegrille: self.millegrille.clone(),
            presentement_valide: self.presentement_valide,
            fingerprint: self.fingerprint.clone(),
            date_enveloppe: self.date_enveloppe.clone(),
            extensions_millegrille: self.extensions_millegrille.clone(),
        }
    }

    fn clone_from(&mut self, source: &Self) {

        let mut intermediaire = Stack::new().expect("stack");
        for cert in &source.intermediaire {
            intermediaire.push(cert.to_owned()).expect("push");
        }

        self.certificat = source.certificat.clone();
        self.chaine = source.chaine.clone();
        self.cle_publique = source.cle_publique.clone();
        self.intermediaire = intermediaire;
        self.millegrille = source.millegrille.clone();
        self.presentement_valide = source.presentement_valide;
        self.fingerprint = source.fingerprint.clone();
        self.date_enveloppe = source.date_enveloppe.clone();
        self.extensions_millegrille = source.extensions_millegrille.clone();
    }

}

impl Debug for EnveloppeCertificat {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Enveloppe certificat {}", self.fingerprint)
    }
}

#[derive(Clone, Debug)]
pub struct FingerprintCert {
    pub fingerprint: String,
    pub pem: String,
}

#[derive(Clone, Debug)]
pub struct FingerprintCertPublicKey {
    pub fingerprint: String,
    pub public_key: PKey<Public>,
    pub est_cle_millegrille: bool,
}

impl FingerprintCertPublicKey {
    pub fn new(fingerprint: String, public_key: PKey<Public>, est_cle_millegrille: bool) -> Self {
        FingerprintCertPublicKey { fingerprint, public_key, est_cle_millegrille }
    }
}

/// Enveloppe avec cle pour cle et certificat combine
#[derive(Clone)]
pub struct EnveloppePrivee {
    pub enveloppe: Arc<EnveloppeCertificat>,
    cle_privee: PKey<Private>,
    chaine_pem: Vec<String>,
    pub clecert_pem: String,
    pub ca: String,
    pub enveloppe_ca: Arc<EnveloppeCertificat>,
}


impl EnveloppePrivee {

    pub fn new(
        enveloppe: Arc<EnveloppeCertificat>,
        cle_privee: PKey<Private>,
        chaine_pem: Vec<String>,
        clecert_pem: String,
        ca: String,
        enveloppe_ca: Arc<EnveloppeCertificat>
    ) -> Self {
        Self { enveloppe, cle_privee, chaine_pem, clecert_pem, ca, enveloppe_ca }
    }

    pub fn certificat(&self) -> &X509 { &self.enveloppe.certificat }

    pub fn chaine_pem(&self) -> &Vec<String> { &self.chaine_pem }

    pub fn cle_privee(&self) -> &PKey<Private> { &self.cle_privee }

    pub fn cle_publique(&self) -> &PKey<Public> { &self.enveloppe.cle_publique }

    pub fn presentement_valide(&self) -> bool { self.enveloppe.presentement_valide }

    pub fn fingerprint(&self) -> &String { self.enveloppe.fingerprint() }

    pub fn intermediaire(&self) -> &Stack<X509> { &self.enveloppe.intermediaire }

    pub fn get_pem_vec(&self) -> Vec<FingerprintCert> { self.enveloppe.get_pem_vec() }

    pub fn idmg(&self) -> Result<String, String> { self.enveloppe.idmg() }

    pub fn subject(&self) -> Result<HashMap<String, String>, String> { self.enveloppe.subject() }

    pub fn not_valid_before(&self) -> Result<DateTime<Utc>, String> { self.enveloppe.not_valid_before() }

    pub fn not_valid_after(&self) -> Result<DateTime<Utc>, String> { self.enveloppe.not_valid_after() }

    pub fn fingerprint_pk(&self) -> Result<String, String> { self.enveloppe.fingerprint_pk() }
    pub fn get_exchanges(&self) -> Result<&Option<Vec<String>>, String> { self.enveloppe.get_exchanges() }
    pub fn get_roles(&self) -> Result<&Option<Vec<String>>, String> { self.enveloppe.get_roles() }
    pub fn get_domaines(&self) -> Result<&Option<Vec<String>>, String> {  self.enveloppe.get_domaines() }
    pub fn get_user_id(&self) -> Result<&Option<String>, String> {  self.enveloppe.get_user_id() }
    pub fn get_delegation_globale(&self) -> Result<&Option<String>, String> {  self.enveloppe.get_delegation_globale() }
    pub fn get_delegation_domaines(&self) -> Result<&Option<Vec<String>>, String> {  self.enveloppe.get_delegation_domaines() }

}

impl Debug for EnveloppePrivee {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("Enveloppe privee {}", self.fingerprint()).as_str())
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
