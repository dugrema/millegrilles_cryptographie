use std::fmt::Formatter;
use serde_repr::{Deserialize_repr, Serialize_repr};
use serde::de::{Error, Visitor};
use rand;
use rand::Rng;
use serde::Deserializer;
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

impl Into<&str> for &FormatChiffrage {
    fn into(self) -> &'static str {
        match self {
            FormatChiffrage::MGS4 => CONST_MGS4,
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

struct FormatChiffrageOptionVisitor;

impl<'de> Visitor<'de> for FormatChiffrageOptionVisitor {
    type Value = Option<FormatChiffrage>;

    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
        formatter.write_str("string ou u8 pour FormatChiffrage")
    }

    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E> where E: Error {
        self.visit_u8(v as u8)
    }

    fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E> where E: Error {
        match v {
            4 => Ok(Some(FormatChiffrage::MGS4)),
            _ => Err(Error::custom("Format non supporte"))
        }
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> where E: Error {
        self.visit_u8(v as u8)
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> where E: Error {
        Ok(Some(
            FormatChiffrage::try_from(v)
                .map_err(|_| Error::custom("visit_str Format chiffrage non supporte"))?
        ))
    }

    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E> where E: Error {
        Ok(Some(
            FormatChiffrage::try_from(v)
                .map_err(|_| Error::custom("visit_str Format chiffrage non supporte"))?
        ))
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E> where E: Error {
        Ok(Some(
            FormatChiffrage::try_from(v.as_str())
                .map_err(|_| Error::custom("visit_str Format chiffrage non supporte"))?
        ))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> where E: Error {
        Ok(None)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error> where D: Deserializer<'de> {
        deserializer.deserialize_any(self)
    }
}

pub mod optionformatchiffragestr {
    use serde::{self, Serializer, Deserializer};
    use crate::chiffrage::{FormatChiffrage, FormatChiffrageOptionVisitor};

    pub fn serialize<S>(date: &Option<FormatChiffrage>, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        match date {
            Some(inner) => {
                let value_str: &str = inner.clone().into();
                serializer.serialize_str(value_str)
            },
            None => serializer.serialize_none()
        }
    }

    pub fn deserialize<'de, D>( deserializer: D ) -> Result<Option<FormatChiffrage>, D::Error>
        where D: Deserializer<'de>,
    {
        deserializer.deserialize_option(FormatChiffrageOptionVisitor)
        // match option {
        //     Some(inner) => match inner.try_into() {
        //         Ok(inner) => Ok(Some(inner)),
        //         Err(e) => Err(D::Error::custom(format!("valeur FormatChiffrage non supportee : {}", e)))
        //     },
        //     None => Ok(None)
        // }
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
    use log::info;
    use serde::{Deserialize, Serialize};

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

    #[derive(Serialize, Deserialize)]
    struct TestFormatOption {
        #[serde(with="optionformatchiffragestr")]
        format: Option<FormatChiffrage>
    }
    #[test_log::test]
    fn test_formatchiffrage_serialize_option() {
        let format_some = TestFormatOption { format: Some(FormatChiffrage::MGS4) };
        let format_none = TestFormatOption { format: None };

        let some_str = serde_json::to_string(&format_some).unwrap();
        info!("FormatChiffrage some {}", some_str);
        let _format_some_deser: TestFormatOption = serde_json::from_str(some_str.as_str()).unwrap();

        let none_str = serde_json::to_string(&format_none).unwrap();
        info!("FormatChiffrage none {}", none_str);
        let _format_none_deser: TestFormatOption = serde_json::from_str(none_str.as_str()).unwrap();

        let some_u8 = "{\"format\": 4}";
        let _format_u8: TestFormatOption = serde_json::from_str(some_u8).unwrap();
    }
}
