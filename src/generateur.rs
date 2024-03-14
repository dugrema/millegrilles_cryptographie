use core::str::{from_utf8, FromStr};
use log::error;
use ed25519_dalek::SigningKey;
use heapless::{String, Vec};

use crate::ed25519::{MessageId, signer_into};
use crate::hachages::{HacheurInterne, HacheurBlake2s256};
use crate::messages_structs::{MessageKind, MessageMilleGrillesRef, RoutageMessage};

const CONST_ELEMS_MAX: usize = 10;

type VecElements<'a> = Vec<&'a [u8], CONST_ELEMS_MAX>;


pub struct MessageMilleGrillesBuilder<'a, const C: usize> {
    kind: MessageKind,
    contenu: &'a str,
    routage: Option<RoutageMessage<'a>>,
}

impl<'a, const C: usize> MessageMilleGrillesBuilder<'a, C> {

    pub fn new(kind: MessageKind, contenu: &'a str) -> Self {
        Self {kind, contenu, routage: None}
    }

    pub fn routage(mut self, routage: RoutageMessage<'a>) -> Self {
        self.routage = Some(routage);
        self
    }

    pub fn build_into<const B: usize>(buffer: &'a mut String<B>) -> MessageMilleGrillesRef<'a, C> {
        buffer.clear();
        panic!()
    }
}

pub struct GenerateurMessageMilleGrilles {}

impl GenerateurMessageMilleGrilles {

    #[cfg(feature = "std")]
    /// Generer un nouveau message MilleGrilles signe sous forme json.
    fn generer<const C: usize>(buffer: &mut [u8], builder: MessageMilleGrillesBuilder<C>) -> Result<std::string::String, ()> {
        todo!()
    }

    fn generer_into<const B: usize, const C: usize>(buffer: &mut String<B>, builder: MessageMilleGrillesBuilder<C>) -> Result<(), ()> {

        Ok(())
    }

    fn generer_id<'a>(elems: &VecElements) -> Result<String<64>, &'static str> {
        let mut hacheur = HacheurBlake2s256::new();
        for elem in elems {
            hacheur.update(elem);
        }
        let mut buffer = [0u8; 32];
        hacheur.finalize_into(&mut buffer);

        let mut buffer_str = [0u8; 64];
        if let Err(e) = hex::encode_to_slice(&buffer, &mut buffer_str) {
            error!("generer_id Erreur conversion vers hex {:?}", e);
            Err("generer_id:E1")?
        }

        let str_val = match from_utf8(&buffer_str) {
            Ok(inner) => inner,
            Err(e) => {
                error!("generer_id Erreur conversion hex vers utf-8 {:?}", e);
                Err("generer_id:E2")?
            }
        };

        match String::from_str(str_val) {
            Ok(inner) => Ok(inner),
            Err(e) => {
                error!("generer_id Erreur conversion String::from_str {:?}", e);
                Err("generer_id:E3")?
            }
        }
    }

    fn signer(id: &str, signing_key: &SigningKey) -> Result<String<128>, &'static str> {
        // Convertir id en bytes
        let mut id_bytes = [0u8; 32] as MessageId;
        if let Err(e) = hex::decode_to_slice(id.as_bytes(), &mut id_bytes) {
            error!("Hex error sur id {} : {:?}", id, e);
            Err("signer:E1")?
        }

        let mut signature_buffer = [0u8; 128];
        let signature_str = signer_into(&signing_key, &id_bytes, &mut signature_buffer);

        match String::from_str(signature_str) {
            Ok(inner) => Ok(inner),
            Err(()) => Err("signer:E2")?
        }
    }
}
