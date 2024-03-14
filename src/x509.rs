use x509_cert::der;
use x509_cert::Certificate;
use x509_cert::certificate::TbsCertificateInner;

use der::DecodePem;

pub fn charger_certificat(pem: &str) -> TbsCertificateInner {
    let pem_bytes = pem.as_bytes();
    let cert = Certificate::from_pem(pem_bytes).unwrap();
    let tbs_cert = cert.tbs_certificate;
    tbs_cert
}

#[cfg(test)]
mod x509_tests {
    use core::str::{from_utf8, FromStr};
    use heapless::String;
    use log::debug;
    use x509_cert::der::Encode;
    use super::*;

    const CERT_1: &str = r#"-----BEGIN CERTIFICATE-----
MIICXzCCAhGgAwIBAgIUdBydrTh7w+g8cAm5Tvj09cCw03IwBQYDK2VwMHIxLTAr
BgNVBAMTJGY4NjFhYWZkLTUyOTctNDA2Zi04NjE3LWY3Yjg4MDlkZDQ0ODFBMD8G
A1UEChM4emVZbmNScUVxWjZlVEVtVVo4d2hKRnVIRzc5NmVTdkNUV0U0TTQzMml6
WHJwMjJiQXR3R203SmYwHhcNMjQwMjIwMTE0NjIzWhcNMjQwMzIyMTE0NjQzWjCB
gjEtMCsGA1UEAwwkZjg2MWFhZmQtNTI5Ny00MDZmLTg2MTctZjdiODgwOWRkNDQ4
MQ4wDAYDVQQLDAVuZ2lueDFBMD8GA1UECgw4emVZbmNScUVxWjZlVEVtVVo4d2hK
RnVIRzc5NmVTdkNUV0U0TTQzMml6WHJwMjJiQXR3R203SmYwKjAFBgMrZXADIQBU
NLrvwdVPPNbT78ihOPgrV2td+ZOsR8zGPVAg3YTQvKOBpzCBpDANBgQqAwQBBAVu
Z2lueDBTBgNVHREETDBKgh50aGlua2NlbnRyZTEubWFwbGUubWFjZXJvYy5jb22C
BW5naW54gglsb2NhbGhvc3SHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEwHwYDVR0j
BBgwFoAUUFGzqm7EHF5p5N/pqKppNT1zhiowHQYDVR0OBBYEFDgS6iNLrfcjpE8q
ni31E23AGCGxMAUGAytlcANBAGBZgTiPh2umqtOQ1t1tz+yRGux1eaBD7COZSi0T
0kuBDa/1VYvbruYdSCRV3yzotunW2tpBpkh8kPkpAMQG2wg=
-----END CERTIFICATE-----"#;

    const CERT_1_INT: &str = r#"-----BEGIN CERTIFICATE-----
MIIBozCCAVWgAwIBAgIKAnY5ZhNJUlVzaTAFBgMrZXAwFjEUMBIGA1UEAxMLTWls
bGVHcmlsbGUwHhcNMjQwMTMwMTM1NDU3WhcNMjUwODEwMTM1NDU3WjByMS0wKwYD
VQQDEyRmODYxYWFmZC01Mjk3LTQwNmYtODYxNy1mN2I4ODA5ZGQ0NDgxQTA/BgNV
BAoTOHplWW5jUnFFcVo2ZVRFbVVaOHdoSkZ1SEc3OTZlU3ZDVFdFNE00MzJpelhy
cDIyYkF0d0dtN0pmMCowBQYDK2VwAyEAPUMU7tlz3HCEB+VzG8NVFQ/nFKjIOZmV
egt+ub3/7SajYzBhMBIGA1UdEwEB/wQIMAYBAf8CAQAwCwYDVR0PBAQDAgEGMB0G
A1UdDgQWBBRQUbOqbsQcXmnk3+moqmk1PXOGKjAfBgNVHSMEGDAWgBTTiP/MFw4D
DwXqQ/J2LLYPRUkkETAFBgMrZXADQQB6S4tids+r9e5d+mwpdkrAE2k3+8H0x65z
WD5eP7A2XeEr0LbxRPNyaO+Q8fvnjjCKasn97MTPSCXnU/4JbWYK
-----END CERTIFICATE-----"#;

    const CERT_MILLEGRILLE: &str = r#"-----BEGIN CERTIFICATE-----
MIIBQzCB9qADAgECAgoHBykXJoaCCWAAMAUGAytlcDAWMRQwEgYDVQQDEwtNaWxs
ZUdyaWxsZTAeFw0yMjAxMTMyMjQ3NDBaFw00MjAxMTMyMjQ3NDBaMBYxFDASBgNV
BAMTC01pbGxlR3JpbGxlMCowBQYDK2VwAyEAnnixameVCZAzfx4dO+L63DOk/34I
/TC4fIA1Rxn19+KjYDBeMA8GA1UdEwEB/wQFMAMBAf8wCwYDVR0PBAQDAgLkMB0G
A1UdDgQWBBTTiP/MFw4DDwXqQ/J2LLYPRUkkETAfBgNVHSMEGDAWgBTTiP/MFw4D
DwXqQ/J2LLYPRUkkETAFBgMrZXADQQBSb0vXhw3pw25qrWoMjqROjawe7/kMlu7p
MJyb/Ppa2C6PraSVPgJGWKl+/5S5tBr58KFNg+0H94CH4d1VCPwI
-----END CERTIFICATE-----"#;

    #[test_log::test]
    fn test_charger_certificat() {
        let cert_leaf = charger_certificat(CERT_1);

        // Extraire information
        let name = cert_leaf.subject;
        for item in name.0 {
            let mut buffer_name = [0u8; 100];
            // let item_name = item.to_string();
            let name_bytes = item.encode_to_slice(&mut buffer_name).unwrap();
            let name_string: String<100> = String::from_str(from_utf8(name_bytes).unwrap()).unwrap();
            let mut vals = name_string.split("=");
            let key = vals.next();
            let value = vals.next();
            debug!("Cert subject {:?} = {:?}", key, value);
        }

        for item in cert_leaf.extensions.unwrap() {
            debug!("Extension {:?} = {:?}", item.extn_id, from_utf8(item.extn_value.as_bytes()));
        }

        let pk = cert_leaf.subject_public_key_info;
        let public_key = pk.subject_public_key.as_bytes().unwrap();
        debug!("Cert public key : {:?}", hex::encode(public_key));
    }

}
