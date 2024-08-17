use snowbridge_amcl::{bls381::{big::Big, ecp::ECP}, rand::RAND};

pub struct PublicKey(pub ECP);
pub struct SigningKey(pub Big);

impl SigningKey {
    pub fn new(big: Big) -> Self {
        Self(big)
    }

    pub fn random(rng: &mut RAND) -> Self {
        Self(Big::random(rng))
    }
}

impl PublicKey {
    pub fn new(point: ECP) -> Self {
        Self(point)
    }

    pub fn from_signing_key(signing_key: &SigningKey) -> Self {
        Self(ECP::generator().mul(&signing_key.0))
    }
}