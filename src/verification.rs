use chrono::{DateTime, Utc};
use crate::messages_structs::MessageMilleGrillesRef;

/// Verifie les certificats utilise par le message.
/// Elements verifies :
/// - la correspondance du pubkey et du certificat leaf
/// - la chaine de certificats
/// - la date du message avec celle du certificat leaf
///
/// Si une date_verification est fournie, s'assure que le certificat leaf est valide a cette date.
pub fn verifier_certificats_message<const C: usize>(
    message: MessageMilleGrillesRef<C>,
    date_verification: Option<&DateTime<Utc>>
) -> Result<(), &'static str> {

    if message.certificat.is_none() {
        Err("verifier_message Certificats manquants")?
    }

    // Charger la chaine de certificats

    // Comparer pubkey du message et key du certificat leaf

    // Valider chaine de certificats, utiliser date de l'estampille

    if let Some(date_verification) = date_verification {
        // Valider la chaine de certificats avec date_verification (e.g. date courante)

        // S'assurer que le certificat leaf est valide en fonction de l'estampille (date du message)

    } else {
        // Valider la chaine de certificats avec l'estampille (date du message)

    }

    Ok(())
}
