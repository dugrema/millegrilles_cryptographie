use std::collections::{BTreeMap, HashMap, HashSet};
use std::error;
use std::fmt::{Debug, Formatter};
use std::fs::read_to_string;
use std::path::Path;
use std::sync::{Arc, Mutex};
use chrono::{DateTime, Utc};
use log::{debug, error, info};
use openssl::error::ErrorStack;
use openssl::pkey::PKey;
use openssl::x509::store::{X509Store, X509StoreBuilder};
use openssl::x509::verify::X509VerifyFlags;
use openssl::x509::X509;
use serde::{Deserialize, Serialize, Serializer};
use crate::x509::{calculer_fingerprint, charger_certificat, charger_enveloppe, EnveloppeCertificat, EnveloppePrivee, ExtensionsMilleGrille, verifier_certificat};

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
    // let fingerprint = calculer_fingerprint(cert).expect("fingerprint");

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

    // let cle_publique = cert.public_key().unwrap();
    // let cert_der = cert.to_der().expect("Erreur exporter cert format DEV");
    // let extensions = parse_x509(cert_der.as_slice()).expect("Erreur preparation extensions X509 MilleGrille");

    Ok(EnveloppeCertificat {
        certificat: cert.clone(),
        chaine: chaine_x509,
        millegrille,
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

pub fn build_store_path(ca_path: &Path) -> Result<ValidateurX509Impl, ErrorStack> {
    let ca_pem: String = read_to_string(ca_path).unwrap();
    let ca_cert: X509 = charger_certificat(&ca_pem)?;
    let store: X509Store = build_store(&ca_cert, true)?;
    let store_notime: X509Store = build_store(&ca_cert, false)?;

    let enveloppe_ca = charger_enveloppe(&ca_pem, Some(&store), None).unwrap();

    // Calculer idmg
    let idmg: String = calculer_idmg(&ca_cert).unwrap();

    let validateur = ValidateurX509Impl::new(store, store_notime, idmg, ca_pem, ca_cert);

    // Conserver l'enveloppe dans le cache
    let _ = validateur.cacher(enveloppe_ca);

    Ok(validateur)
}

pub fn build_store(ca_cert: &X509, check_time: bool) -> Result<X509Store, ErrorStack> {
    let mut builder = X509StoreBuilder::new()?;
    let ca_cert = ca_cert.to_owned();  // Requis par methode add_cert
    let _ = builder.add_cert(ca_cert);

    if check_time == false {
        // Verification manuelle de la date de validite.
        builder.set_flags(X509VerifyFlags::NO_CHECK_TIME).expect("set_flags");
    }

    Ok(builder.build())
}

pub fn charger_enveloppe_privee<V>(path_cert: &Path, path_cle: &Path, validateur: Arc<V>)
                                   -> Result<EnveloppePrivee, ErrorStack>
    where V: ValidateurX509
{
    let path_cle_str = format!("cle : {:?}", path_cle);
    let pem_cle = read_to_string(path_cle).expect(path_cle_str.as_str());
    // let cle_privee = Rsa::private_key_from_pem(pem_cle.as_bytes())?;
    // let cle_privee: PKey<Private> = PKey::from_rsa(cle_privee)?;
    let cle_privee = PKey::private_key_from_pem(pem_cle.as_bytes())?;

    let pem_cert = read_to_string(path_cert).unwrap();
    let enveloppe = charger_enveloppe(&pem_cert, Some(validateur.store()), None)?;

    let clecert_pem = format!("{}\n{}", pem_cle, pem_cert);

    // Recreer la chaine de certificats avec les PEM.
    let mut chaine_pem: Vec<String> = Vec::new();
    let cert_pem = String::from_utf8(enveloppe.certificat().to_pem().unwrap()).unwrap();
    chaine_pem.push(cert_pem);
    for cert_intermediaire in &enveloppe.intermediaire {
        let pem = cert_intermediaire.to_pem().unwrap();
        let cert_pem = String::from_utf8(pem).unwrap();
        chaine_pem.push(cert_pem);
    }

    let ca_pem = validateur.ca_pem().to_owned();
    let enveloppe_ca = Arc::new(charger_enveloppe(&ca_pem, Some(validateur.store()), None)?);
    let enveloppe_privee = EnveloppePrivee {
        enveloppe: Arc::new(enveloppe),
        cle_privee,
        chaine_pem,
        clecert_pem,
        ca: ca_pem,
        enveloppe_ca,
    };

    Ok(enveloppe_privee)
}

#[async_trait]
pub trait ValidateurX509: Send + Sync {

    async fn charger_enveloppe(&self, chaine_pem: &Vec<String>, fingerprint: Option<&str>, ca_pem: Option<&str>) -> Result<Arc<EnveloppeCertificat>, String>;

    /// Conserve un certificat dans le cache
    /// retourne le certificat et un bool qui indique si le certificat a deja ete persiste (true)
    async fn cacher(&self, certificat: EnveloppeCertificat) -> (Arc<EnveloppeCertificat>, bool);

    /// Set le flag persiste a true pour le certificat correspondant a fingerprint
    fn set_flag_persiste(&self, fingerprint: &str);

    async fn get_certificat(&self, fingerprint: &str) -> Option<Arc<EnveloppeCertificat>>;

    /// Retourne une liste de certificats qui n'ont pas encore ete persiste.
    fn certificats_persister(&self) -> Vec<Arc<EnveloppeCertificat>>;

    fn idmg(&self) -> &str;

    fn ca_pem(&self) -> &str;

    fn ca_cert(&self) -> &X509;

    fn store(&self) -> &X509Store;

    /// Store avec le flag X509VerifyFlags::NO_CHECK_TIME
    /// Permet de valider une date specifique
    /// Todo: utiliser OpenSSL lorsque verif params disponibles
    fn store_notime(&self) -> &X509Store;

    /// Invoquer regulierement pour faire l'entretien du cache.
    async fn entretien_validateur(&self);

    fn valider_chaine(&self, enveloppe: &EnveloppeCertificat, certificat_millegrille: Option<&EnveloppeCertificat>) -> Result<bool, String> {
        let certificat = &enveloppe.certificat;
        let chaine = &enveloppe.intermediaire;
        match certificat_millegrille {
            Some(cm) => {
                debug!("Idmg tiers, on bati un store on the fly : CA {:?}", cm.chaine);
                let cert_ca = &cm.certificat;
                // let cert_ca = chaine[chaine.len()-1].to_owned();
                let store = match build_store(cert_ca, false) {
                    Ok(s) => s,
                    Err(_e) => Err(format!("certificats.valider_chaine Erreur preparation store pour certificat {:?}", certificat))?
                };
                match verifier_certificat(certificat, chaine, &store) {
                    Ok(b) => {
                        debug!("Verifier certificat result : valide = {}, cert {:?}", b, certificat);
                        Ok(b)
                    },
                    Err(e) => Err(format!("certificats.valider_chaine Erreur verification certificat idmg {:?} : {:?}", certificat, e)),
                }
            },
            None => {
                match verifier_certificat(certificat, chaine, self.store_notime()) {
                    Ok(b) => {
                        debug!("Verifier certificat result apres check date OK : {}", b);
                        Ok(b)
                    },
                    Err(e) => Err(format!("certificats.valider_chaine Erreur verification certificat avec no time : {:?}", e)),
                }
            }
        }
    }

    /// Valider le certificat pour une fourchette de date.
    /// Note : ne valide pas la chaine
    fn valider_pour_date(&self, enveloppe: &EnveloppeCertificat, date: &DateTime<Utc>) -> Result<bool, String> {
        let before = enveloppe.not_valid_before()?;
        let after = enveloppe.not_valid_after()?;
        Ok(date >= &before && date <= &after)
    }

}

pub struct ValidateurX509Impl {
    store: X509Store,
    store_notime: X509Store,
    idmg: String,
    ca_pem: String,
    ca_cert: X509,
    cache_certificats: Mutex<HashMap<String, CacheCertificat>>,
}

impl ValidateurX509Impl {

    pub fn new(store: X509Store, store_notime: X509Store, idmg: String, ca_pem: String, ca_cert: X509) -> ValidateurX509Impl {
        let cache_certificats: Mutex<HashMap<String, CacheCertificat>> = Mutex::new(HashMap::new());
        ValidateurX509Impl {store, store_notime, idmg, ca_pem, ca_cert, cache_certificats}
    }

    /// Expose la fonction pour creer un certificat
    fn charger_certificat(pem: &str) -> Result<(X509, String), String> {
        let cert = charger_certificat(pem);
        let fingerprint = calculer_fingerprint(&cert)?;
        Ok((cert, fingerprint))
    }

}

#[async_trait]
impl ValidateurX509 for ValidateurX509Impl {

    async fn charger_enveloppe(&self, chaine_pem: &Vec<String>, fingerprint: Option<&str>, ca_pem: Option<&str>)
                               -> Result<Arc<EnveloppeCertificat>, String>
    {

        let fp: String = match fingerprint {
            Some(fp) => Ok(String::from(fp)),
            None => {
                debug!("charger_enveloppe Charger le _certificat pour trouver fingerprint");
                match chaine_pem.get(0) {
                    Some(pem) => {
                        match ValidateurX509Impl::charger_certificat(pem.as_str()) {
                            Ok(r) => Ok(r.1),
                            Err(e) => Err(format!("Erreur chargement enveloppe certificat : {:?}", e)),
                        }
                    },
                    None => Err(String::from("Aucun certificat n'est present")),
                }
            }
        }?;

        debug!("charger_enveloppe Fingerprint du certificat de l'enveloppe a charger : {}", fp);

        // Verifier si le certificat est present dans le cache
        match self.get_certificat(fp.as_str()).await {
            Some(e) => Ok(e),
            None => {
                // Creer l'enveloppe et conserver dans le cache local
                let pem_str: String = chaine_pem.join("\n");
                debug!("charger_enveloppe Alignement du _certificat en string concatenee\n{}", pem_str);
                match charger_enveloppe(pem_str.as_str(), Some(&self.store), ca_pem) {
                    Ok(e) => {

                        // Verifier si on a un certificat de millegrille tierce (doit avoir CA)
                        let idmg_local = self.idmg.as_str();
                        if e.est_ca()? {
                            // Certificat CA, probablement d'une millegrille tierce. Accepter inconditionnellement.
                            Ok(self.cacher(e).await.0)
                        } else {
                            // Verifier si le certificat est local (CA n'est pas requis)
                            // Pour tiers, le CA doit etre inclus dans l'enveloppe.
                            let idmg_certificat = e.idmg()?;
                            if idmg_local == idmg_certificat.as_str() || e.millegrille.is_some() {
                                Ok(self.cacher(e).await.0)
                            } else {
                                Err(format!("certificats.charger_enveloppe Erreur chargement certificat {} : certificat CA manquant pour millegrille {} tierce", fp, idmg_certificat))
                            }
                        }
                    },
                    Err(e) => Err(format!("certificats.charger_enveloppe Erreur chargement certificat {} : {:?}", fp, e))
                }
            }
        }
    }

    async fn cacher(&self, certificat: EnveloppeCertificat) -> (Arc<EnveloppeCertificat>, bool) {

        let fingerprint = certificat.fingerprint().clone();

        let mut mutex = self.cache_certificats.lock().expect("lock");
        match mutex.get_mut(fingerprint.as_str()) {
            Some(e) => {
                // Incrementer compteur, maj date acces
                e.compte_acces = e.compte_acces + 1;
                e.dernier_acces = Utc::now();

                (e.enveloppe.clone(), e.persiste)
            },
            None => {
                let enveloppe = Arc::new(certificat);

                if mutex.len() < TAILLE_CACHE_MAX {
                    // Certificat inconnu, sauvegarder dans le cache
                    let cache_entry = CacheCertificat::new(enveloppe.clone());
                    mutex.insert(fingerprint, cache_entry);
                } else {
                    debug!("Cache certificat plein, on ne conserve pas le certificat en memoire");
                }

                // Retourne l'enveloppe et indicateur que le certificat n'est pas persiste
                (enveloppe, false)
            }
        }
    }

    fn set_flag_persiste(&self, fingerprint: &str) {
        let mut mutex = self.cache_certificats.lock().expect("lock");
        if let Some(certificat) = mutex.get_mut(fingerprint) {
            certificat.persiste = true;
        }
    }

    async fn get_certificat(&self, fingerprint: &str) -> Option<Arc<EnveloppeCertificat>> {
        match self.cache_certificats.lock().unwrap().get_mut(fingerprint) {
            Some(e) => {
                // Incrementer compteur, maj date acces
                e.compte_acces = e.compte_acces + 1;
                e.dernier_acces = Utc::now();

                // Retourner clone de l'enveloppe
                Some(e.enveloppe.clone())
            },
            None => None,
        }
    }

    /// Retourne une liste de certificats qui n'ont pas encore ete persiste.
    fn certificats_persister(&self) -> Vec<Arc<EnveloppeCertificat>> {
        let mut mutex = self.cache_certificats.lock().expect("lock");
        mutex.iter()
            .filter(|(_,c)| !c.persiste)
            .map(|e| e.1.enveloppe.clone())
            .collect()
    }

    fn idmg(&self) -> &str { self.idmg.as_str() }

    fn ca_pem(&self) -> &str { self.ca_pem.as_str() }

    fn ca_cert(&self) -> &X509 { &self.ca_cert }

    fn store(&self) -> &X509Store { &self.store }

    fn store_notime(&self) -> &X509Store { &self.store_notime }

    async fn entretien_validateur(&self) {
        debug!("Entretien cache certificats");

        {
            let mut mutex = self.cache_certificats.lock().expect("lock");
            if mutex.len() > TAILLE_CACHE_NETTOYER {
                // Retirer tous les certificats avec une date d'acces expiree (cache mode MRU)
                let expiration = Utc::now() - chrono::Duration::minutes(30);
                mutex.retain(|_, val| val.dernier_acces < expiration);

                if mutex.len() > TAILLE_CACHE_MAX {
                    // Meme apres nettoyage d'expiration, le cache est plus grand que la limite max
                    mutex.clear();  // On fait juste clearer le cache. TODO faire un menage correct
                }
            }
        }
    }

}

impl Debug for ValidateurX509Impl {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("validateur X509")
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

    fn verifier(&self, exchanges: Option<Vec<Securite>>, roles: Option<Vec<RolesCertificats>>) -> bool {
        let mut valide = true;

        if let Some(e) = exchanges {
            valide = valide && self.verifier_exchanges(e);
        }

        if let Some(r) = roles {
            valide = valide && self.verifier_roles(r);
        }

        valide
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
        let exchanges_string: Vec<String> = exchanges_permis.into_iter().map(|s| s.try_into().expect("securite")).collect();
        self.verifier_exchanges_string(exchanges_string)
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

    /// Verifie les roles des certificats
    fn verifier_roles(&self, roles_permis: Vec<RolesCertificats>) -> bool {
        let roles_string: Vec<String> = roles_permis.into_iter().map(|s| s.try_into().expect("securite")).collect();
        self.verifier_roles_string(roles_string)
    }

    fn verifier_roles_string(&self, roles_permis: Vec<String>) -> bool {
        // Valider certificat.
        let extensions = match self.get_extensions() {
            Some(e) => e,
            None => return false
        };

        let mut hs_param= HashSet::new();
        hs_param.extend(roles_permis);

        let hs_cert = match extensions.roles.clone() {
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

impl VerificateurPermissions for EnveloppeCertificat {
    fn get_extensions(&self) -> Option<&ExtensionsMilleGrille> {
        Some(&self.extensions_millegrille)
    }
}

pub fn ordered_map<S>(value: &HashMap<String, String>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
{
    let ordered: BTreeMap<_, _> = value.iter().collect();
    ordered.serialize(serializer)
}

/// Structure qui permet d'exporter en Json plusieurs certificats en format PEM.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CollectionCertificatsPem {
    certificats: Vec<Vec<String>>,
    #[serde(serialize_with = "ordered_map")]
    pems: HashMap<String, String>,
}

impl CollectionCertificatsPem {

    pub fn new() -> Self {
        CollectionCertificatsPem {
            pems: HashMap::new(),
            certificats: Vec::new(),
        }
    }

    pub fn ajouter_certificat(&mut self, certificat: &EnveloppeCertificat) -> Result<(), Box<dyn error::Error>> {
        let fingerprint = &certificat.fingerprint;

        match self.pems.get(fingerprint) {
            Some(_) => {
                // Ok, rien a faire
                return Ok(())
            },
            None => ()
        }

        let mut chaine_fp = Vec::new();
        for fp_cert in certificat.get_pem_vec() {
            chaine_fp.push(fp_cert.fingerprint.clone());
            self.pems.insert(fp_cert.fingerprint, fp_cert.pem);
        }

        self.certificats.push(chaine_fp);

        Ok(())
    }

    pub fn len(&self) -> usize {
        self.certificats.len()
    }

    pub async fn get_enveloppe(&self, validateur: &impl ValidateurX509, fingerprint_certificat: &str) -> Option<Arc<EnveloppeCertificat>> {
        // Trouver la chaine avec le fingerprint (position 0)
        let res_chaine = self.certificats.iter().filter(|chaine| {
            if let Some(fp) = chaine.get(0) {
                fp.as_str() == fingerprint_certificat
            } else {
                false
            }
        }).next();

        // Generer enveloppe a partir des PEMs individuels
        if let Some(chaine) = res_chaine {
            debug!("Fingerprints trouves (chaine): {:?}", chaine);
            let pems: Vec<String> = chaine.into_iter().map(|fp| self.pems.get(fp.as_str()).expect("pem").to_owned()).collect();
            match validateur.charger_enveloppe(&pems, Some(fingerprint_certificat), None).await {
                Ok(e) => Some(e),
                Err(e) => {
                    error!("Erreur chargement enveloppe {} : {:?}", fingerprint_certificat, e);
                    None
                },
            }
        } else {
            None
        }

    }
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
