// use std::convert::TryFrom;
// use std::error::Error;

use log::debug;
use multibase::{Base, decode, encode};
// use multihash::{Code, Multihash, MultihashDigest, Sha2_256, Sha2_512, Blake2b512, Blake2s256, StatefulHasher};
use multihash::Multihash;
use serde::Serialize;
use serde_json_core::{ser::to_string, de::from_str, de::from_slice};
use uuid::Uuid;
use blake2::{Blake2s256, Blake2b512, Digest};
use sha2::{Sha256, Sha512};

const SHA2_256: u16 = 0x12;
const SHA2_512: u16 = 0x13;
const BLAKE2B_512: u16 = 0xb240;
const BLAKE2S_256: u16 = 0xb260;


pub enum HachageCode {
    Sha2_256,
    Sha2_512,
    Blake2s256,
    Blake2b512,
}

fn hachagecode_value(code: HachageCode) -> u16 {
    match code {
        HachageCode::Sha2_256 => SHA2_256,
        HachageCode::Sha2_512 => SHA2_512,
        HachageCode::Blake2s256 => BLAKE2S_256,
        HachageCode::Blake2b512 => BLAKE2B_512
    }
}

// pub fn hacher_serializable<S>(s: &S) -> Result<String, Box<dyn Error>>
//     where S: Serialize
// {
//     let value = serde_json::to_value(s)?;
//     let ser_bytes = serde_json::to_vec(&value)?;
//     Ok(hacher_bytes(ser_bytes.as_slice(), Some(Code::Blake2b512), Some(Base::Base64)))
// }

// pub fn hacher_bytes(contenu: &[u8], code: Option<Code>, base: Option<Base>) -> String {
//     let digester: Code;
//     match code {
//         Some(inner) => digester = inner,
//         None => digester = Code::Blake2b512,
//     }
//
//     // Digest direct (une passe)
//     let mh_digest = digester.digest(contenu);
//     let mh_bytes = mh_digest.to_bytes();
//
//     let base_mb: Base;
//     match base {
//         Some(inner) => base_mb = inner,
//         None => base_mb = Base::Base64,
//     }
//     let valeur_hachee = encode(base_mb, mh_bytes);
//
//     valeur_hachee
// }

pub fn hacher_bytes_into<T>(contenu: &[u8], code: T, output: &mut [u8])
    where T: Into<Option<HachageCode>>
{
    let code = code.into().unwrap_or_else(|| HachageCode::Blake2b512);
    match code {
        HachageCode::Sha2_256 => {
            let mut hacheur = HacheurSha2_256::new();
            hacheur.update(contenu);
            hacheur.finalize_into(output);
        },
        HachageCode::Sha2_512 =>  {
            let mut hacheur = HacheurSha2_512::new();
            hacheur.update(contenu);
            hacheur.finalize_into(output);
        },
        HachageCode::Blake2s256 => {
            let mut hacheur = HacheurBlake2s256::new();
            hacheur.update(contenu);
            hacheur.finalize_into(output);
        },
        HachageCode::Blake2b512 => {
            let mut hacheur = HacheurBlake2b512::new();
            hacheur.update(contenu);
            hacheur.finalize_into(output);
        }
    };
}

#[cfg(feature = "std")]
pub fn hacher_bytes<T>(contenu: &[u8], code: T) -> Vec<u8>
    where T: Into<Option<HachageCode>>
{
    let code = code.into().unwrap_or_else(|| HachageCode::Blake2b512);
    let mut output = [0u8; 68];
    match code {
        HachageCode::Blake2s256 => {
            hacher_bytes_into(contenu, code, &mut output);
            output[0..36].to_vec()
        },
        HachageCode::Blake2b512 =>  {
            hacher_bytes_into(contenu, code, &mut output);
            output.to_vec()
        }
        HachageCode::Sha2_256 => {
            hacher_bytes_into(contenu, code, &mut output);
            output[0..34].to_vec()
        },
        HachageCode::Sha2_512 => {
            hacher_bytes_into(contenu, code, &mut output);
            output[0..66].to_vec()
        },
    }
}

// pub fn verifier_hachage_serializable<S>(hachage: &[u8], code: Code, s: &S) -> Result<bool, Box<dyn Error>>
//     where S: Serialize
// {
//     let value = serde_json::to_value(s)?;
//
//     let ser_bytes = serde_json::to_vec(&value)?;
//     debug!("Verification hachage message {}", String::from_utf8(ser_bytes.clone()).expect("string"));
//
//     let mh_digest = code.digest(ser_bytes.as_slice());
//     let hachage_calcule: &[u8] = mh_digest.digest(); // to_bytes();
//
//     // Enlever 2 premiers bytes (multibase et multihash)
//     // let hachage_calcule = mh_bytes.as_slice();  //[2..];
//
//     debug!("Hachage comparaison recu/calcule\n{:?}\n{:?}", hachage, hachage_calcule);
//
//     Ok(hachage_calcule == hachage)
// }
//
// pub fn verifier_multihash(hachage: &str, contenu: &[u8]) -> Result<bool, Box<dyn Error>> {
//     // let mb = "mEiDhIyaO8TdBnmXKWeih9o+ASND5t8VgZfqDjLan8lT7xg";
//     debug!("Verifier multihash {}", hachage);
//
//     // Extraire multihash bytes de l'input string en multibase
//     let mb_bytes = decode(hachage)?;
//
//     // Extraire le code et digest du multihash
//     let mh = Multihash::from_bytes(&mb_bytes.1)?;
//     let digest = mh.digest();
//     let code = mh.code();
//     debug!("Chargement multihash, code {:x}, \ndigest: {:02x?}", code, digest);
//
//     // Recalculer le digest avec le contenu
//     let digester = Code::try_from(code)?;
//
//     debug!("Type de digest {:?}", digester);
//
//     let digest_calcule = digester.digest(contenu);
//     let digest_bytes = digest_calcule.digest();
//
//     debug!("Resultat digest recalcule : \ndigest: {:02x?}", digest_bytes);
//
//     let correspond = digest == digest_bytes;
//
//     Ok(correspond)
// }
//
// pub struct Hacheur {
//     hacheur_interne: Box<dyn HacheurInterne>,
//     code: HachageCode,
//     base: Base,
//     pub hachage_bytes: Option<String>,
// }
//
// impl Hacheur {
//     pub fn builder() -> HacheurBuilder {
//         HacheurBuilder::new()
//     }
//
//     pub fn update(&mut self, data: &[u8]) {
//         self.hacheur_interne.update(data)
//     }
//
//     pub fn finalize(&mut self) -> String {
//         match &self.hachage_bytes {
//             Some(h) => h.clone(),
//             None => {
//                 let mh_bytes = self.hacheur_interne.finalize();
//                 let hachage_bytes = encode(self.base, mh_bytes);
//                 self.hachage_bytes = Some(hachage_bytes.clone());
//
//                 hachage_bytes
//             }
//         }
//     }
// }
//
// pub struct HacheurBuilder {
//     code: HachageCode,
//     base: Base,
// }
//
// impl HacheurBuilder {
//     pub fn new() -> Self {
//         HacheurBuilder {
//             code: HachageCode::Blake2b512,
//             base: Base::Base64,
//         }
//     }
//
//     pub fn code(mut self, code: HachageCode) -> Self {
//         self.code = code;
//         self
//     }
//
//     pub fn base(mut self, base: Base) -> Self {
//         self.base = base;
//         self
//     }
//
//     pub fn build(self) -> Hacheur {
//
//         let hacheur_interne: Box<dyn HacheurInterne> = match u64::from(self.digester) {
//             0x12 => Box::new(HacheurSha2_256{hacheur: Sha2_256::default()}),
//             0x13 => Box::new(HacheurSha2_512{hacheur: Sha2_512::default()}),
//             0xb240 => Box::new(HacheurBlake2b_512{hacheur: Blake2b512::default()}),
//             0xb260 => Box::new(HacheurBlake2s_256{hacheur: Blake2s256::default()}),
//             _ => panic!("Type hacheur inconnu")
//         };
//
//         Hacheur{
//             hacheur_interne,
//             digester: self.digester,
//             base: self.base,
//             hachage_bytes: None,
//         }
//     }
// }

trait HacheurInterne: Send {
    fn new() -> Self where Self: Sized;
    fn update(&mut self, data: &[u8]);
    fn finalize_into(self, output: &mut [u8]);
    #[cfg(feature = "std")]
    fn finalize(self) -> Vec<u8>;
}

// #[derive(Debug)]
// struct HacheurSha2_256 { hacheur: Sha2_256 }
// impl HacheurInterne for HacheurSha2_256 {
//     fn new() -> Self { HacheurSha2_256{hacheur: Sha2_256::default()} }
//     fn update(&mut self, data: &[u8]) { self.hacheur.update(data) }
//     fn finalize(&mut self) -> Vec<u8> {
//         let digest = self.hacheur.finalize();
//         let mh = Code::multihash_from_digest(&digest);
//         mh.to_bytes().to_owned()
//     }
// }
//
// #[derive(Debug)]
// struct HacheurSha2_512 { hacheur: Sha2_512 }
// impl HacheurInterne for HacheurSha2_512 {
//     fn new() -> Self { HacheurSha2_512{hacheur: Sha2_512::default()} }
//     fn update(&mut self, data: &[u8]) { self.hacheur.update(data) }
//     fn finalize(&mut self) -> Vec<u8> {
//         let digest = self.hacheur.finalize();
//         let mh = Code::multihash_from_digest(&digest);
//         mh.to_bytes().to_owned()
//     }
// }

struct HacheurBlake2b512 { hacheur: Blake2b512 }
impl HacheurInterne for HacheurBlake2b512 {
    fn new() -> Self { HacheurBlake2b512{hacheur: Blake2b512::default()} }
    fn update(&mut self, data: &[u8]) { self.hacheur.update(data) }
    fn finalize_into(mut self, output: &mut [u8]) {
        let mut output_hachage = [0u8; 64];
        self.hacheur.finalize_into((&mut output_hachage).into());
        let mh: Multihash<64> = Multihash::wrap(BLAKE2B_512 as u64, &output_hachage).expect("multihash wrap");
        mh.write(output).unwrap();
    }
    #[cfg(feature = "std")]
    fn finalize(mut self) -> Vec<u8> {
        let mut output = [0u8; 68];  // hash 64 bytes + 4 bytes multihash
        self.finalize_into(&mut output);
        output.to_vec()
    }
}

struct HacheurBlake2s256 { hacheur: Blake2s256 }
impl HacheurInterne for HacheurBlake2s256 {
    fn new() -> Self { HacheurBlake2s256 {hacheur: Blake2s256::default()} }
    fn update(&mut self, data: &[u8]) { self.hacheur.update(data) }
    fn finalize_into(mut self, output: &mut [u8]) {
        let mut output_hachage = [0u8; 32];
        self.hacheur.finalize_into((&mut output_hachage).into());
        let mh: Multihash<32> = Multihash::wrap(BLAKE2S_256 as u64, &output_hachage).expect("multihash wrap");
        mh.write(output).unwrap();
    }
    #[cfg(feature = "std")]
    fn finalize(mut self) -> Vec<u8> {
        let mut output = [0u8; 36];  // hash 32 bytes + 4 bytes multihash
        self.finalize_into(&mut output);
        output.to_vec()
    }
}

struct HacheurSha2_256 { hacheur: Sha256 }
impl HacheurInterne for HacheurSha2_256 {
    fn new() -> Self { HacheurSha2_256 {hacheur: Sha256::default()} }
    fn update(&mut self, data: &[u8]) { self.hacheur.update(data) }
    fn finalize_into(mut self, output: &mut [u8]) {
        let mut output_hachage = [0u8; 32];
        self.hacheur.finalize_into((&mut output_hachage).into());
        let mh: Multihash<32> = Multihash::wrap(SHA2_256 as u64, &output_hachage).expect("multihash wrap");
        mh.write(output).unwrap();
    }
    #[cfg(feature = "std")]
    fn finalize(mut self) -> Vec<u8> {
        let mut output = [0u8; 36];  // hash 64 bytes + 4 bytes multihash
        self.finalize_into(&mut output);
        output.to_vec()
    }
}

struct HacheurSha2_512 { hacheur: Sha512 }
impl HacheurInterne for HacheurSha2_512 {
    fn new() -> Self { HacheurSha2_512 {hacheur: Sha512::default()} }
    fn update(&mut self, data: &[u8]) { self.hacheur.update(data) }
    fn finalize_into(mut self, output: &mut [u8]) {
        let mut output_hachage = [0u8; 64];
        self.hacheur.finalize_into((&mut output_hachage).into());
        let mh: Multihash<64> = Multihash::wrap(SHA2_512 as u64, &output_hachage).expect("multihash wrap");
        mh.write(output).unwrap();
    }

    #[cfg(feature = "std")]
    fn finalize(mut self) -> Vec<u8> {
        let mut output = [0u8; 68];  // hash 64 bytes + 4 bytes multihash
        self.finalize_into(&mut output);
        output.to_vec()
    }
}

// #[derive(Debug)]
// struct HacheurBlake2s_256 { hacheur: Blake2s256 }
// impl HacheurInterne for HacheurBlake2s_256 {
//     fn new() -> Self { HacheurBlake2s_256{hacheur: Blake2s256::default()} }
//     fn update(&mut self, data: &[u8]) { self.hacheur.update(data) }
//     fn finalize(&mut self) -> Vec<u8> {
//         let digest = self.hacheur.finalize();
//         let mh = Code::multihash_from_digest(&digest);
//         mh.to_bytes().to_owned()
//     }
// }
//
// /// Hachage d'un UUID format string - extrait UUID en bytes pour hacher
// pub fn hacher_uuid<S>(uuid_in: S, len_bytes: Option<u8>) -> Result<String, uuid::Error>
//     where S: AsRef<str>
// {
//     let uuid_str = uuid_in.as_ref();
//     let uuid_val = Uuid::parse_str(uuid_str)?;
//     let uuid_bytes = uuid_val.as_bytes();
//
//     let len_hachage = match len_bytes {
//         Some(l) => l,
//         None => 12
//     };
//
//     // let hachage_str = hacher_bytes(
//     //     uuid_bytes, Some(Code::Sha2_256), Some(Base::Base64));
//
//     let mut hacheur = Sha2_256::default();
//     hacheur.update(uuid_bytes);
//     let hachage = hacheur.finalize();
//     let hachage_str: String = multibase::encode(Base::Base58Btc, hachage.as_ref());
//     debug!("hacher_uuid str : {}", hachage_str);
//
//     Ok(String::from(hachage_str.substring(1, (len_hachage+1) as usize)))
// }

#[cfg(test)]
mod hachage_tests {
    use super::*;

    use hex;

    #[test]
    #[cfg(feature = "std")]
    fn hacheur_blake2b() {
        let data = b"Test Data";
        let hachage = hacher_bytes(&data[..], HachageCode::Blake2b512);
        let hex_hachage = hex::encode(hachage);
        assert_eq!("c0e40240dc0cf45e507173abe4c7169e7786e9fbfd7cbaefdc192e924139fb34632a6c12c904c7caa3e7f51e842dcd1a4addf767e95d883b55efe33c9e47d185b95f2374", hex_hachage);
    }

    #[test]
    fn hacheur_blake2b_into() {
        let data = b"Test Data2";
        let mut hachage = [0u8; 68];  // 64 bytes Blake2b + 4 bytes multihash
        hacher_bytes_into(&data[..], HachageCode::Blake2b512, &mut hachage);
        let hex_hachage = hex::encode(hachage);
        assert_eq!("c0e40240d63640c6f5533be864dfe4aab925045a26b36cf55d0c1c8427bdc7e31413c5a59ef7ba751d7de85530c23163e811cc13af442fc3d6f8cbd4b2fb42a02132760c", hex_hachage);
    }

    #[test]
    #[cfg(feature = "std")]
    fn hacheur_blake2s() {
        let data = b"Test Data3";
        let hachage = hacher_bytes(&data[..], HachageCode::Blake2s256);
        let hex_hachage = hex::encode(hachage);
        assert_eq!("e0e4022065312b4006f89ea5a0d9e8fe41952685fa80504ab2eeb334fa92a4a7d479e93c", hex_hachage);
    }

    #[test]
    fn hacheur_blake2s_into() {
        let data = b"Test Data4";
        let mut hachage = [0u8; 36];  // 32 bytes Blake2b + 4 bytes multihash
        hacher_bytes_into(&data[..], HachageCode::Blake2s256, &mut hachage);
        let hex_hachage = hex::encode(hachage);
        assert_eq!("e0e40220a85426ed4c67864062f314df7a9212bf7b72033ed06c24a4c475e90bc90fd533", hex_hachage);
    }

    #[test]
    #[cfg(feature = "std")]
    fn hacheur_sha2_256() {
        let data = b"Test Data5";
        let hachage = hacher_bytes(&data[..], HachageCode::Sha2_256);
        let hex_hachage = hex::encode(hachage);
        assert_eq!("1220b966de3a9f0f40876ff8873bdbdf76d7d67a24453e7dd353cfd4ff9e7805adaa", hex_hachage);
    }

    #[test]
    fn hacheur_sha2_256_into() {
        let data = b"Test Data5";
        let mut hachage = [0u8; 34];  // 32 bytes Blake2b + 2 bytes multihash
        hacher_bytes_into(&data[..], HachageCode::Sha2_256, &mut hachage);
        let hex_hachage = hex::encode(hachage);
        assert_eq!("1220b966de3a9f0f40876ff8873bdbdf76d7d67a24453e7dd353cfd4ff9e7805adaa", hex_hachage);
    }

    #[test]
    #[cfg(feature = "std")]
    fn hacheur_sha2_512() {
        let data = b"Test Data6";
        let hachage = hacher_bytes(&data[..], HachageCode::Sha2_512);
        let hex_hachage = hex::encode(hachage);
        assert_eq!("1340c44c1fa41850d7cff60cf097da10145a0a757c32c2fcd3737f3e7d69413cd5315680a1122b1c52095973afbf6d6531954f2341b5c1e0aec7b5c5a408b080c0e0", hex_hachage);
    }

    #[test]
    fn hacheur_sha2_512_into() {
        let data = b"Test Data6";
        let mut hachage = [0u8; 66];  // 64 bytes Blake2b + 2 bytes multihash
        hacher_bytes_into(&data[..], HachageCode::Sha2_512, &mut hachage);
        let hex_hachage = hex::encode(hachage);
        assert_eq!("1340c44c1fa41850d7cff60cf097da10145a0a757c32c2fcd3737f3e7d69413cd5315680a1122b1c52095973afbf6d6531954f2341b5c1e0aec7b5c5a408b080c0e0", hex_hachage);
    }

}
