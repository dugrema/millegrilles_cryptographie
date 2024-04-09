/// Macro qui permet de deserialiser le contenu d'un MessageRef ou MessageOwned
#[macro_export(local_inner_macros)]
macro_rules! deser_message_buffer {
    ($message:expr) => {
        {
            let message_ref = $message.parse()?;
            message_ref.contenu()?.deserialize()?
        }
    }
}

#[cfg(test)]
mod macro_tests {
    use serde::Deserialize;
    // use super::*;
    use crate::error::Error;
    use crate::messages_structs::MessageMilleGrillesBufferDefault;

    const MESSAGE_1: &str = r#"{
      "id": "d49a375c980f1e70cdea697664610d70048899d1428909fdc29bd29cfc9dd1ca",
      "pubkey": "d1d9c2146de0e59971249489d971478050d55bc913ddeeba0bf3c60dd5b2cd31",
      "estampille": 1710338722,
      "kind": 5,
      "contenu": "{\"domaine\":\"CoreMaitreDesComptes\",\"exchanges_routing\":null,\"instance_id\":\"f861aafd-5297-406f-8617-f7b8809dd448\",\"primaire\":true,\"reclame_fuuids\":false,\"sous_domaines\":null}",
      "routage": {
        "action": "presenceDomaine",
        "domaine": "CoreMaitreDesComptes"
      },
      "sig": "9ff0c6443c9214ab9e8ee2d26b3ba6453e7f4f5f59477343e1b0cd747535005b13d453922faad1388e65850a1970662a69879b1b340767fb9f4bda6202412204",
      "certificat": [
        "-----BEGIN CERTIFICATE-----\nMIIClDCCAkagAwIBAgIUQuFP9EOrsQuFkWnXEH8UQNZ1EN4wBQYDK2VwMHIxLTAr\nBgNVBAMTJGY4NjFhYWZkLTUyOTctNDA2Zi04NjE3LWY3Yjg4MDlkZDQ0ODFBMD8G\nA1UEChM4emVZbmNScUVxWjZlVEVtVVo4d2hKRnVIRzc5NmVTdkNUV0U0TTQzMml6\nWHJwMjJiQXR3R203SmYwHhcNMjQwMjIwMTE0NjUzWhcNMjQwMzIyMTE0NzEzWjCB\ngTEtMCsGA1UEAwwkZjg2MWFhZmQtNTI5Ny00MDZmLTg2MTctZjdiODgwOWRkNDQ4\nMQ0wCwYDVQQLDARjb3JlMUEwPwYDVQQKDDh6ZVluY1JxRXFaNmVURW1VWjh3aEpG\ndUhHNzk2ZVN2Q1RXRTRNNDMyaXpYcnAyMmJBdHdHbTdKZjAqMAUGAytlcAMhANHZ\nwhRt4OWZcSSUidlxR4BQ1VvJE93uugvzxg3Vss0xo4HdMIHaMCsGBCoDBAAEIzQu\nc2VjdXJlLDMucHJvdGVnZSwyLnByaXZlLDEucHVibGljMAwGBCoDBAEEBGNvcmUw\nTAYEKgMEAgREQ29yZUJhY2t1cCxDb3JlQ2F0YWxvZ3VlcyxDb3JlTWFpdHJlRGVz\nQ29tcHRlcyxDb3JlUGtpLENvcmVUb3BvbG9naWUwDwYDVR0RBAgwBoIEY29yZTAf\nBgNVHSMEGDAWgBRQUbOqbsQcXmnk3+moqmk1PXOGKjAdBgNVHQ4EFgQU4+j+8rBR\nK+WeiFzo6EIR+t0C7o8wBQYDK2VwA0EAab2vFykbUk1cWugRd10rGiTKp/PKZdG5\nX+Y+lrHe8AHcrpGGtUV8mwwcDsRbw2wtRq2ENceNlQAcwblEkxLvCA==\n-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\nMIIBozCCAVWgAwIBAgIKAnY5ZhNJUlVzaTAFBgMrZXAwFjEUMBIGA1UEAxMLTWls\nbGVHcmlsbGUwHhcNMjQwMTMwMTM1NDU3WhcNMjUwODEwMTM1NDU3WjByMS0wKwYD\nVQQDEyRmODYxYWFmZC01Mjk3LTQwNmYtODYxNy1mN2I4ODA5ZGQ0NDgxQTA/BgNV\nBAoTOHplWW5jUnFFcVo2ZVRFbVVaOHdoSkZ1SEc3OTZlU3ZDVFdFNE00MzJpelhy\ncDIyYkF0d0dtN0pmMCowBQYDK2VwAyEAPUMU7tlz3HCEB+VzG8NVFQ/nFKjIOZmV\negt+ub3/7SajYzBhMBIGA1UdEwEB/wQIMAYBAf8CAQAwCwYDVR0PBAQDAgEGMB0G\nA1UdDgQWBBRQUbOqbsQcXmnk3+moqmk1PXOGKjAfBgNVHSMEGDAWgBTTiP/MFw4D\nDwXqQ/J2LLYPRUkkETAFBgMrZXADQQB6S4tids+r9e5d+mwpdkrAE2k3+8H0x65z\nWD5eP7A2XeEr0LbxRPNyaO+Q8fvnjjCKasn97MTPSCXnU/4JbWYK\n-----END CERTIFICATE-----\n"
      ],
      "attachements": {
        "exemple": {"tada": "toto"},
        "exemple2": "une string"
      }
    }"#;

    #[cfg(feature = "alloc")]
    #[test_log::test]
    fn test_macro() {
        test_macro_wrapper().unwrap();
    }

    #[derive(Deserialize)]
    struct DomaineInfo {
        instance_id: std::string::String,
        domaine: std::string::String,
    }
    fn test_macro_wrapper() -> Result<(), Error> {
        let message_1 = MessageMilleGrillesBufferDefault::from(MESSAGE_1.as_bytes().to_vec());
        let value: DomaineInfo = deser_message_buffer!(message_1);
        assert_eq!("f861aafd-5297-406f-8617-f7b8809dd448", value.instance_id.as_str());
        assert_eq!("CoreMaitreDesComptes", value.domaine.as_str());
        Ok(())
    }

}
