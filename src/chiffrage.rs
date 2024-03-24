use log::info;
use serde_repr::{Deserialize_repr, Serialize_repr};
use rand;
use rand::Rng;
use zeroize::Zeroize;

//pub const MAXLEN_DATA_CHIFFRE: usize = 1024 * 1024 * 3;

pub const CONST_MGS4: &str = "mgs4";

#[derive(Clone, Debug, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum FormatChiffrage {
    MGS4 = 4
}

impl TryFrom<&str> for FormatChiffrage {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            CONST_MGS4 => Ok(Self::MGS4),
            _ => Err("type de chiffrage invalide")?
        }
    }
}

impl Into<&str> for FormatChiffrage {
    fn into(self) -> &'static str {
        match self {
            Self::MGS4 => CONST_MGS4,
        }
    }
}

pub mod formatchiffragestr {

    use serde::{self, Deserialize, Serializer, Deserializer};
    use serde::de::Error;
    use crate::chiffrage::FormatChiffrage;

    pub fn serialize<S>(value: &FormatChiffrage, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        let value_str: &str = value.clone().into();
        serializer.serialize_str(value_str)
    }

    pub fn deserialize<'de, D>( deserializer: D ) -> Result<FormatChiffrage, D::Error>
        where D: Deserializer<'de>,
    {
        let s = std::string::String::deserialize(deserializer)?;
        match s.as_str().try_into() {
            Ok(inner) => Ok(inner),
            Err(e) => Err(D::Error::custom(format!("valeur FormatChiffrage non supportee : {}", e)))
        }
    }
}

#[derive(Clone, PartialEq, Zeroize)]
#[zeroize(drop)]
pub struct CleSecrete<const C: usize>(pub [u8; C]);

impl<const C: usize> CleSecrete<C> {
    pub fn generer() -> Self {
        let mut buffer = [0u8; C];
        let mut rnd = rand::thread_rng();
        rnd.fill(&mut buffer);
        CleSecrete (buffer)
    }
}

pub type CleSecreteMgs4 = CleSecrete<32>;

#[cfg(feature = "alloc")]
/// Genere un Vec de nb_bytes aleatoires.
pub fn random_vec(nb_bytes: usize) -> Vec<u8> {
    let mut v = vec![0; nb_bytes];
    let mut rnd = rand::thread_rng();
    rnd.fill(v.as_mut_slice());
    v
}

/// Genere un Vec de nb_bytes aleatoires.
pub fn random_bytes<const C: usize>() -> [u8; C] {
    let mut buffer = [0u8; C];
    let mut rnd = rand::thread_rng();
    rnd.fill(&mut buffer);
    buffer
}

#[cfg(test)]
mod ed25519_tests {
    use super::*;

    #[test_log::test]
    fn test_clesecrete_generer() {
        let cle_secrete = CleSecreteMgs4::generer();
        info!("Cle secrete generee : {:?}", cle_secrete.0);
        assert_eq!(32, cle_secrete.0.len());
    }

    #[test_log::test]
    fn test_random_vec() {
        const NB_BYTES: usize = 45;
        let resultat = random_vec(NB_BYTES);
        info!("Resultat random : {:?}", resultat);
        assert_eq!(NB_BYTES, resultat.len());
    }

    #[test_log::test]
    fn test_random_bytes() {
        const NB_BYTES: usize = 67;
        let rnd_bytes: [u8; NB_BYTES] = random_bytes();
        info!("Resultat random : {:?}", rnd_bytes);
        assert_eq!(NB_BYTES, rnd_bytes.len());
    }
}
