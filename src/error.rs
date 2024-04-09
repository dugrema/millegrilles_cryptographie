use std::fmt;
use std::str::Utf8Error;
use std::string::FromUtf8Error;
#[cfg(feature = "chiffrage")]
use chacha20poly1305::aead;
#[cfg(feature = "openssl")]
use openssl::error::ErrorStack;
#[cfg(feature = "optional-defaults")]
use multibase;
#[cfg(feature = "dryoc")]
use dryoc;

#[derive(Debug)]
pub enum Error {
    #[cfg(feature = "openssl")]
    Openssl(ErrorStack),
    #[cfg(feature = "optional-defaults")]
    Multibase(multibase::Error),
    #[cfg(feature = "optional-defaults")]
    Multihash(multihash::Error),
    #[cfg(feature = "chiffrage")]
    Chacha20poly1350(aead::Error),
    #[cfg(feature = "dryoc")]
    Dryoc(dryoc::Error),
    SerdeJson(serde_json::Error),
    #[cfg(feature = "std")]
    Io(std::io::Error),
    Utf8Error(Utf8Error),
    FromUtf8(FromUtf8Error),
    #[cfg(feature = "std")]
    String(String),
    Str(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {
}

#[cfg(feature = "openssl")]
impl From<ErrorStack> for Error {
    fn from(value: ErrorStack) -> Self {
        Error::Openssl(value)
    }
}

#[cfg(feature = "chiffrage")]
impl From<aead::Error> for Error {
    fn from(value: chacha20poly1305::Error) -> Self {
        Error::Chacha20poly1350(value)
    }
}

#[cfg(feature = "optional-defaults")]
impl From<multibase::Error> for Error {
    fn from(value: multibase::Error) -> Self {
        Error::Multibase(value)
    }
}

#[cfg(feature = "optional-defaults")]
impl From<multihash::Error> for Error {
    fn from(value: multihash::Error) -> Self {
        Error::Multihash(value)
    }
}

#[cfg(feature = "dryoc")]
impl From<dryoc::Error> for Error {
    fn from(value: dryoc::Error) -> Self {
        Error::Dryoc(value)
    }
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Error::SerdeJson(value)
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Error::Io(value)
    }
}

impl From<FromUtf8Error> for Error {
    fn from(value: FromUtf8Error) -> Self {
        Self::FromUtf8(value)
    }
}

impl From<std::string::String> for Error {
    fn from(value: std::string::String) -> Self {
        Error::String(value)
    }
}

impl Into<std::string::String> for Error {
    fn into(self) -> String {
        format!("millegrilles_cryptographie::Error {:?}", self)
    }
}

impl From<&str> for Error {
    fn from(value: &str) -> Self {
        Self::String(format!("millegrilles_cryptographie::Error {:?}", value))
    }
}

impl From<Utf8Error> for Error {
    fn from(value: Utf8Error) -> Self {
        Self::Utf8Error(value)
    }
}