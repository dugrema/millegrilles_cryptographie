use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Debug;
use std::fs::read_to_string;
use std::path::Path;
use chrono::{DateTime, Utc};
use log::{debug, info, warn};
use openssl::asn1::Asn1TimeRef;
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::stack::{Stack, StackRef};
use openssl::x509::store::{X509Store, X509StoreBuilder};
use openssl::x509::verify::X509VerifyFlags;
use openssl::x509::{X509, X509Ref, X509StoreContext, X509StoreContextRef};
use serde::{Serialize, Serializer};
use crate::securite::Securite;

use crate::x509::{Error, EnveloppeCertificat, ExtensionsMilleGrille, calculer_idmg_ref};

pub trait ValidateurX509: Send + Sync {

    fn valider(&self, enveloppe: &EnveloppeCertificat, date: Option<&DateTime<Utc>>) -> Result<(), Error>;

}

fn verifier_certificat_context(cert: &X509Ref, context: &mut X509StoreContextRef) -> Result<bool, ErrorStack> {
    let mut resultat = context.verify_cert()?;

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
            match context.chain() {
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
}

fn verifier_certificat(cert: &X509, chaine_pem: &StackRef<X509>, store: &X509Store) -> Result<(), Error> {
    let mut store_context = X509StoreContext::new()?;
    let resultat: bool = store_context.init(store, cert, chaine_pem, |c| {
        verifier_certificat_context(cert, c)
    })?;

    if ! resultat {
        Err(Error::Str("Certificat invalide"))?
    }

    Ok(())
}

pub fn build_store_from_path(ca_path: &Path) -> Result<ValidateurX509Impl, Error> {
    let ca_pem: String = read_to_string(ca_path).unwrap();
    build_store_from_str(ca_pem)
}

pub fn build_store_from_str<S>(ca: S) -> Result<ValidateurX509Impl, Error>
    where S: ToString
{
    let ca = ca.to_string();

    let enveloppe_ca = match EnveloppeCertificat::try_from(ca.as_str()) {
        Ok(inner) => inner,
        Err(e) => Err(Error::String(format!("EnveloppePrivee from_str Erreur try_from ca : {:?}", e)))?
    };

    if ! enveloppe_ca.est_ca()? {
        Err(Error::Str("build_store_from_str Enveloppe n'est pas CA"))?
    }

    let ca_cert = enveloppe_ca.certificat.as_ref();
    let store: X509Store = build_store(ca_cert, true)?;
    let store_notime: X509Store = build_store(ca_cert, false)?;

    // Calculer idmg
    let idmg = enveloppe_ca.calculer_idmg()?;

    let validateur = ValidateurX509Impl {
        store,
        store_notime,
        idmg,
        ca_pem: ca,
        ca_cert: enveloppe_ca.certificat,
    };

    Ok(validateur)
}

fn build_store(ca_cert: &X509Ref, check_time: bool) -> Result<X509Store, ErrorStack>
{
    let ca_cert = ca_cert.to_owned();

    let mut builder = X509StoreBuilder::new()?;
    let _ = builder.add_cert(ca_cert);

    if check_time == false {
        // Verification manuelle de la date de validite.
        builder.set_flags(X509VerifyFlags::NO_CHECK_TIME).expect("set_flags");
    }

    Ok(builder.build())
}

pub struct ValidateurX509Impl {
    store: X509Store,
    store_notime: X509Store,
    pub idmg: String,
    pub ca_pem: String,
    pub ca_cert: X509,
}

impl ValidateurX509Impl {

    pub fn new(store: X509Store, store_notime: X509Store, idmg: String, ca_pem: String, ca_cert: X509) -> ValidateurX509Impl {
        ValidateurX509Impl {store, store_notime, idmg, ca_pem, ca_cert}
    }

}

impl ValidateurX509 for ValidateurX509Impl {
    fn valider(&self, enveloppe: &EnveloppeCertificat, date: Option<&DateTime<Utc>>) -> Result<(), Error> {

        let mut intermediaire: Stack<X509> = match Stack::new() {
            Ok(inner) => inner,
            Err(e) => Err(Error::Openssl(e))?
        };

        // Generer chaine intermediaire - skip cert[0] (leaf)
        for cert in &enveloppe.chaine[1..] {
            if let Err(e) = intermediaire.push(cert.to_owned()) {
                Err(Error::Openssl(e))?
            }
        }

        match date {
            Some(inner) => {
                // Valider chaine avec la date recue
                for cert in &enveloppe.chaine {
                    let not_valid_after = match not_valid_after(&cert) {
                        Ok(inner) => inner,
                        Err(e) => Err(Error::String(format!("ValidateurX509Impl::valider Erreur chargement not_valid_after : {:?}", e)))?
                    };
                    let not_valid_before = match not_valid_before(&cert) {
                        Ok(inner) => inner,
                        Err(e) => Err(Error::String(format!("ValidateurX509Impl::valider Erreur chargement not_valid_before : {:?}", e)))?
                    };
                    if &not_valid_before > inner || &not_valid_after < inner {
                        Err(Error::Str("ValidateurX509Impl::valider Certificat hors date"))?
                    }
                }

                // Verifier en ignorant la date
                verifier_certificat(&enveloppe.certificat, intermediaire.as_ref(), &self.store_notime)
            },
            None => {
                // Verifier avec la date courante
                verifier_certificat(&enveloppe.certificat, intermediaire.as_ref(), &self.store)
            }
        }
    }
}

pub fn not_valid_before(cert: &X509) -> Result<DateTime<Utc>, Error> {
    let not_before: &Asn1TimeRef = cert.not_before();
    match EnveloppeCertificat::formatter_date_epoch(not_before) {
        Ok(date) => Ok(date),
        Err(e) => Err(Error::String(format!("Parsing erreur certificat not_valid_before : {:?}", e)))
    }
}

pub fn not_valid_after(cert: &X509) -> Result<DateTime<Utc>, Error> {
    let not_after: &Asn1TimeRef = cert.not_after();
    match EnveloppeCertificat::formatter_date_epoch(not_after) {
        Ok(date) => Ok(date),
        Err(e) => Err(Error::String(format!("Parsing erreur certificat not_valid_after : {:?}", e)))
    }
}

pub trait VerificateurPermissions {
    fn get_extensions(&self) -> Option<&ExtensionsMilleGrille>;

    fn get_user_id(&self) -> Option<String> {
        match self.get_extensions() {
            Some(e) => {
                e.user_id.to_owned()
            },
            None => None
        }
    }

    fn verifier_usager<S>(&self, user_id: S) -> bool
        where S: AsRef<str>
    {
        let extensions = match self.get_extensions() {
            Some(e) => e,
            None => return false
        };

        match &extensions.user_id {
            Some(u) => u.as_str() == user_id.as_ref(),
            None => false
        }
    }

    fn verifier_delegation_globale<S>(&self, delegation: S) -> bool
        where S: AsRef<str>
    {
        let extensions = match self.get_extensions() {
            Some(e) => e,
            None => return false
        };

        match &extensions.delegation_globale {
            Some(inner) => inner.as_str() == delegation.as_ref(),
            None => false
        }
    }

    fn verifier_exchanges(&self, exchanges_permis: Vec<Securite>) -> bool {
        // Valider certificat.
        let exchanges_string: Vec<&str> = exchanges_permis.into_iter().map(|s| s.into()).collect();
        self.verifier_exchanges_string(exchanges_string.into_iter().map(|s| s.to_string()).collect())
    }

    fn verifier_exchanges_string(&self, exchanges_permis: Vec<String>) -> bool {
        // Valider certificat.
        let extensions = match self.get_extensions() {
            Some(e) => e,
            None => return false
        };
        debug!("verifier_exchanges_string Extensions cert : {:?}", extensions);

        let mut hs_param= HashSet::new();
        hs_param.extend(exchanges_permis);

        let hs_cert = match extensions.exchanges.clone() {
            Some(ex) => {
                let mut hs_cert = HashSet::new();
                hs_cert.extend(ex);
                hs_cert
            },
            None => return false,
        };

        let res: Vec<&String> = hs_param.intersection(&hs_cert).collect();
        // let res: Vec<&String> = exchanges_permis.iter().filter(|c| ex.contains(c)).collect();
        if res.len() == 0 {
            return false
        }

        true
    }

    fn verifier_roles_string<S>(&self, roles_permis: Vec<S>) -> bool
        where S: ToString
    {
        // Valider certificat.
        let extensions = match self.get_extensions() {
            Some(e) => e,
            None => return false
        };

        let mut hs_param= HashSet::new();
        for r in roles_permis {
            hs_param.insert(r.to_string());
        }
        // hs_param.extend(roles_permis);

        let hs_cert = match extensions.roles.as_ref() {
            Some(ex) => {
                let mut hs_cert = HashSet::new();
                for r in ex {
                    hs_cert.insert(r.to_owned());
                }
                hs_cert
            },
            None => return false,
        };

        let res: Vec<&String> = hs_param.intersection(&hs_cert).collect();
        if res.len() == 0 {
            return false
        }

        true
    }

    fn verifier_domaines(&self, domaines_permis: Vec<String>) -> bool {
        // Valider certificat.
        let extensions = match self.get_extensions() {
            Some(e) => e,
            None => return false
        };

        let mut hs_param= HashSet::new();
        hs_param.extend(domaines_permis);

        let hs_cert = match extensions.domaines.clone() {
            Some(ex) => {
                let mut hs_cert = HashSet::new();
                hs_cert.extend(ex);
                hs_cert
            },
            None => return false,
        };

        let res: Vec<&String> = hs_param.intersection(&hs_cert).collect();
        if res.len() == 0 {
            return false
        }

        true
    }

}

pub fn ordered_map<S>(value: &HashMap<String, String>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
{
    let ordered: BTreeMap<_, _> = value.iter().collect();
    ordered.serialize(serializer)
}

#[derive(Debug)]
pub struct VerificateurRegles<'a> {
    /// Regles "or", une seule regle doit etre valide
    pub regles_disjointes: Option<Vec<Box<dyn RegleValidation + 'a>>>,
    /// Regles "and", toutes doivent etre valides
    pub regles_conjointes: Option<Vec<Box<dyn RegleValidation + 'a>>>
}

impl<'a> VerificateurRegles<'a> {

    pub fn new() -> Self {
        VerificateurRegles { regles_disjointes: None, regles_conjointes: None }
    }

    pub fn ajouter_conjointe<R>(&mut self, regle: R) where R: RegleValidation + 'a {
        let regles = match &mut self.regles_conjointes {
            Some(r) => r,
            None => {
                self.regles_conjointes = Some(Vec::new());
                match &mut self.regles_conjointes { Some(r) => r, None => panic!("vec mut")}
            }
        };
        regles.push(Box::new(regle));
    }

    pub fn ajouter_disjointe<R>(&mut self, regle: R) where R: RegleValidation + 'a {
        let regles = match &mut self.regles_disjointes {
            Some(r) => r,
            None => {
                self.regles_disjointes = Some(Vec::new());
                match &mut self.regles_disjointes { Some(r) => r, None => panic!("vec mut")}
            }
        };
        regles.push(Box::new(regle));
    }

    pub fn verifier(&self, certificat: &EnveloppeCertificat) -> bool {
        // Verifier conjonction
        if let Some(regles) = &self.regles_conjointes {
            for r in regles {
                if ! r.verifier(certificat) {
                    return false;  // Court-circuit
                }
            }
            // Toutes les regles sont true
        }

        // Verifier disjonction
        if let Some(regles) = &self.regles_disjointes {
            for r in regles {
                if r.verifier(certificat) {
                    return true;  // Court-circuit
                }
            }

            // Aucunes des regles "or" n'a ete true
            return false
        }

        // Toutes les regles "and" et "or" sont true
        true
    }

}

pub trait RegleValidation: Debug + Send + Sync {
    /// Retourne true si la regle est valide pour ce certificat
    fn verifier(&self, certificat: &EnveloppeCertificat) -> bool;
}

/// Regle de validation pour un IDMG tiers
#[derive(Debug)]
pub struct RegleValidationIdmg { pub idmg: String }
impl RegleValidation for RegleValidationIdmg {
    fn verifier(&self, certificat: &EnveloppeCertificat) -> bool {
        match certificat.idmg() {
            Ok(i) => i.as_str() == self.idmg.as_str(),
            Err(e) => {
                info!("RegleValidationIdmg Erreur verification idmg : {:?}", e);
                false
            }
        }
    }
}


#[cfg(test)]
mod messages_structs_tests {
    use super::*;
    use log::info;

    const CERT_1: &str = r#"-----BEGIN CERTIFICATE-----
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

    const CERT_INTER: &str = r#"-----BEGIN CERTIFICATE-----
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

    const CERT_CA: &str = r#"-----BEGIN CERTIFICATE-----
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
    fn test_try_from_str_chaine() {
        let chaine = vec![CERT_1, CERT_INTER].join("\n");
        let validateur = build_store_from_str(CERT_CA).unwrap();
        let cert = EnveloppeCertificat::try_from(chaine.as_str()).unwrap();
        info!("Certificat charge OK : {}", cert.fingerprint().unwrap());

        // Valider. Lance une exception s'il y a une erreur.
        validateur.valider(&cert, None).unwrap();
    }

    #[test_log::test]
    fn test_try_from_str_chaine_incomplete() {
        let validateur = build_store_from_str(CERT_CA).unwrap();
        let cert = EnveloppeCertificat::try_from(CERT_1).unwrap();
        info!("Certificat charge OK : {}", cert.fingerprint().unwrap());

        // Valider. Lance une exception s'il y a une erreur.
        assert!(validateur.valider(&cert, None).is_err());
    }

    #[test_log::test]
    fn test_valider_certificat_date() {
        let chaine = vec![CERT_1, CERT_INTER].join("\n");
        let validateur = build_store_from_str(CERT_CA).unwrap();
        let cert = EnveloppeCertificat::try_from(chaine.as_str()).unwrap();
        info!("Certificat charge OK : {}", cert.fingerprint().unwrap());

        // Valider. Lance une exception s'il y a une erreur.
        let date = DateTime::from_timestamp(1710338722, 0).unwrap();
        assert!(validateur.valider(&cert, Some(&date)).is_ok());
    }

    #[test_log::test]
    fn test_valider_certificat_date_invalide() {
        let chaine = vec![CERT_1, CERT_INTER].join("\n");
        let validateur = build_store_from_str(CERT_CA).unwrap();
        let cert = EnveloppeCertificat::try_from(chaine.as_str()).unwrap();
        info!("Certificat charge OK : {}", cert.fingerprint().unwrap());

        // Valider. Lance une exception s'il y a une erreur.
        let date = DateTime::from_timestamp(1500000000, 0).unwrap();
        assert!(validateur.valider(&cert, Some(&date)).is_err());
    }
}
