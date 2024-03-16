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
    #[cfg(feature = "std")]
    String(String),
    Str(&'static str),
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
