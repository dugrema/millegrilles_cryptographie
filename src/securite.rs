#[derive(Clone, Debug)]
pub enum Securite {
    L1Public = 1,
    L2Prive = 2,
    L3Protege = 3,
    L4Secure = 4,
}

const L1_PUBLIC: &str = "1.public";
const L2_PRIVE: &str = "2.prive";
const L3_PROTEGE: &str = "3.protege";
const L4_SECURE: &str = "4.secure";

impl TryFrom<&str> for Securite {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            L1_PUBLIC => Ok(Securite::L1Public),
            L2_PRIVE => Ok(Securite::L2Prive),
            L3_PROTEGE => Ok(Securite::L3Protege),
            L4_SECURE => Ok(Securite::L4Secure),
            _ => Err("niveau de securite invalide")?
        }
    }
}
