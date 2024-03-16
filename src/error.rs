use chacha20poly1305::aead;
use openssl::error::ErrorStack;
use multibase;
use dryoc;

#[derive(Debug)]
pub enum Error {
    #[cfg(feature = "openssl")]
    Openssl(ErrorStack),
    #[cfg(feature = "optional-defaults")]
    Multibase(multibase::Error),
    #[cfg(feature = "chiffrage")]
    Chacha20poly1350(aead::Error),
    #[cfg(feature = "dryoc")]
    Dryoc(dryoc::Error),
    String(String),
    Str(&'static str),
}

impl From<ErrorStack> for Error {
    fn from(value: ErrorStack) -> Self {
        Error::Openssl(value)
    }
}

impl From<aead::Error> for Error {
    fn from(value: chacha20poly1305::Error) -> Self {
        Error::Chacha20poly1350(value)
    }
}

impl From<multibase::Error> for Error {
    fn from(value: multibase::Error) -> Self {
        Error::Multibase(value)
    }
}

impl From<dryoc::Error> for Error {
    fn from(value: dryoc::Error) -> Self {
        Error::Dryoc(value)
    }
}
