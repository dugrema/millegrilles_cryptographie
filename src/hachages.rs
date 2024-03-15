use blake2::{Blake2s256, Blake2b512, Digest};
use sha2::{Sha256, Sha512};

const SHA2_256: u16 = 0x12;
const SHA2_512: u16 = 0x13;
const BLAKE2B_512: u16 = 0xb240;
const BLAKE2S_256: u16 = 0xb260;


pub enum HachageCode {
    Sha2_256 = SHA2_256 as isize,
    Sha2_512 = SHA2_512 as isize,
    Blake2s256 = BLAKE2S_256 as isize,
    Blake2b512 = BLAKE2B_512 as isize,
}

// fn hachagecode_value(code: HachageCode) -> u16 {
//     match code {
//         HachageCode::Sha2_256 => SHA2_256,
//         HachageCode::Sha2_512 => SHA2_512,
//         HachageCode::Blake2s256 => BLAKE2S_256,
//         HachageCode::Blake2b512 => BLAKE2B_512
//     }
// }

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
    let mut output = [0u8; 64];
    match code {
        HachageCode::Blake2s256 => {
            hacher_bytes_into(contenu, code, &mut output[0..32]);
            output[0..32].to_vec()
        },
        HachageCode::Blake2b512 =>  {
            hacher_bytes_into(contenu, code, &mut output);
            output.to_vec()
        }
        HachageCode::Sha2_256 => {
            hacher_bytes_into(contenu, code, &mut output[0..32]);
            output[0..32].to_vec()
        },
        HachageCode::Sha2_512 => {
            hacher_bytes_into(contenu, code, &mut output);
            output.to_vec()
        },
    }
}

pub trait HacheurInterne: Send {
    fn new() -> Self where Self: Sized;
    fn update(&mut self, data: &[u8]);
    fn finalize_into(self, output: &mut [u8]);
}

pub struct HacheurBlake2b512 { hacheur: Blake2b512 }
impl HacheurInterne for HacheurBlake2b512 {
    fn new() -> Self { HacheurBlake2b512{hacheur: Blake2b512::default()} }
    fn update(&mut self, data: &[u8]) { self.hacheur.update(data) }
    fn finalize_into(self, output: &mut [u8]) {
        let mut output_hachage = [0u8; 64];
        self.hacheur.finalize_into((&mut output_hachage).into());
        output.copy_from_slice(&output_hachage[..]);
    }
}

pub struct HacheurBlake2s256 { hacheur: Blake2s256 }
impl HacheurInterne for HacheurBlake2s256 {
    fn new() -> Self { HacheurBlake2s256 {hacheur: Blake2s256::default()} }
    fn update(&mut self, data: &[u8]) { self.hacheur.update(data) }
    fn finalize_into(self, output: &mut [u8]) {
        let mut output_hachage = [0u8; 32];
        self.hacheur.finalize_into((&mut output_hachage).into());
        output.copy_from_slice(&output_hachage[..]);
    }
}

pub struct HacheurSha2_256 { hacheur: Sha256 }
impl HacheurInterne for HacheurSha2_256 {
    fn new() -> Self { HacheurSha2_256 {hacheur: Sha256::default()} }
    fn update(&mut self, data: &[u8]) { self.hacheur.update(data) }
    fn finalize_into(self, output: &mut [u8]) {
        let mut output_hachage = [0u8; 32];
        self.hacheur.finalize_into((&mut output_hachage).into());
        output.copy_from_slice(&output_hachage[..]);
    }
}

pub struct HacheurSha2_512 { hacheur: Sha512 }
impl HacheurInterne for HacheurSha2_512 {
    fn new() -> Self { HacheurSha2_512 {hacheur: Sha512::default()} }
    fn update(&mut self, data: &[u8]) { self.hacheur.update(data) }
    fn finalize_into(self, output: &mut [u8]) {
        let mut output_hachage = [0u8; 64];
        self.hacheur.finalize_into((&mut output_hachage).into());
        output.copy_from_slice(&output_hachage[..]);
    }
}

#[cfg(test)]
mod hachage_tests {
    use core::str::from_utf8;
    use super::*;

    use hex;

    #[test_log::test]
    #[cfg(feature = "std")]
    fn hacheur_blake2b() {
        let data = b"Test Data";
        let hachage = hacher_bytes(&data[..], HachageCode::Blake2b512);
        let hex_hachage = hex::encode(hachage);
        assert_eq!("dc0cf45e507173abe4c7169e7786e9fbfd7cbaefdc192e924139fb34632a6c12c904c7caa3e7f51e842dcd1a4addf767e95d883b55efe33c9e47d185b95f2374", hex_hachage);
    }

    #[test_log::test]
    fn hacheur_blake2b_into() {
        let data = b"Test Data2";
        let mut hachage = [0u8; 64];  // 64 bytes Blake2b
        hacher_bytes_into(&data[..], HachageCode::Blake2b512, &mut hachage);
        let mut buf_hachage = [0u8; 128];
        hex::encode_to_slice(hachage, &mut buf_hachage).unwrap();
        let hex_hachage = from_utf8(&buf_hachage).unwrap();
        assert_eq!("d63640c6f5533be864dfe4aab925045a26b36cf55d0c1c8427bdc7e31413c5a59ef7ba751d7de85530c23163e811cc13af442fc3d6f8cbd4b2fb42a02132760c", hex_hachage);
    }

    #[test_log::test]
    #[cfg(feature = "std")]
    fn hacheur_blake2s() {
        let data = b"Test Data3";
        let hachage = hacher_bytes(&data[..], HachageCode::Blake2s256);
        let mut buf_hachage = [0u8; 64];
        hex::encode_to_slice(hachage, &mut buf_hachage).unwrap();
        let hex_hachage = from_utf8(&buf_hachage).unwrap();
        assert_eq!("65312b4006f89ea5a0d9e8fe41952685fa80504ab2eeb334fa92a4a7d479e93c", hex_hachage);
    }

    #[test_log::test]
    fn hacheur_blake2s_into() {
        let data = b"Test Data4";
        let mut hachage = [0u8; 32];  // 32 bytes Blake2s
        hacher_bytes_into(&data[..], HachageCode::Blake2s256, &mut hachage);
        let mut buf_hachage = [0u8; 64];
        hex::encode_to_slice(hachage, &mut buf_hachage).unwrap();
        let hex_hachage = from_utf8(&buf_hachage).unwrap();
        assert_eq!("a85426ed4c67864062f314df7a9212bf7b72033ed06c24a4c475e90bc90fd533", hex_hachage);
    }

    #[test_log::test]
    #[cfg(feature = "std")]
    fn hacheur_sha2_256() {
        let data = b"Test Data5";
        let hachage = hacher_bytes(&data[..], HachageCode::Sha2_256);
        let mut buf_hachage = [0u8; 64];
        hex::encode_to_slice(hachage, &mut buf_hachage).unwrap();
        let hex_hachage = from_utf8(&buf_hachage).unwrap();
        assert_eq!("b966de3a9f0f40876ff8873bdbdf76d7d67a24453e7dd353cfd4ff9e7805adaa", hex_hachage);
    }

    #[test_log::test]
    fn hacheur_sha2_256_into() {
        let data = b"Test Data5";
        let mut hachage = [0u8; 32];  // 32 bytes Sha2_256
        hacher_bytes_into(&data[..], HachageCode::Sha2_256, &mut hachage);
        let mut buf_hachage = [0u8; 64];
        hex::encode_to_slice(hachage, &mut buf_hachage).unwrap();
        let hex_hachage = from_utf8(&buf_hachage).unwrap();
        assert_eq!("b966de3a9f0f40876ff8873bdbdf76d7d67a24453e7dd353cfd4ff9e7805adaa", hex_hachage);
    }

    #[test_log::test]
    #[cfg(feature = "std")]
    fn hacheur_sha2_512() {
        let data = b"Test Data6";
        let hachage = hacher_bytes(&data[..], HachageCode::Sha2_512);
        let hex_hachage = hex::encode(hachage);
        assert_eq!("c44c1fa41850d7cff60cf097da10145a0a757c32c2fcd3737f3e7d69413cd5315680a1122b1c52095973afbf6d6531954f2341b5c1e0aec7b5c5a408b080c0e0", hex_hachage);
    }

    #[test_log::test]
    fn hacheur_sha2_512_into() {
        let data = b"Test Data6";
        let mut hachage = [0u8; 64];  // 64 bytes Sha2_512
        hacher_bytes_into(&data[..], HachageCode::Sha2_512, &mut hachage);
        let mut buf_hachage = [0u8; 128];
        hex::encode_to_slice(hachage, &mut buf_hachage).unwrap();
        let hex_hachage = from_utf8(&buf_hachage).unwrap();
        assert_eq!("c44c1fa41850d7cff60cf097da10145a0a757c32c2fcd3737f3e7d69413cd5315680a1122b1c52095973afbf6d6531954f2341b5c1e0aec7b5c5a408b080c0e0", hex_hachage);
    }

}
