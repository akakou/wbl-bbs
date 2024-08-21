use snowbridge_amcl::{
    bls381::{big::Big, ecp2::ECP2},
    rand::RAND,
};

pub struct Parameters {
    pub g0: ECP2,
    pub g1: ECP2,
    pub h0: ECP2,
    pub h1: ECP2,
}

impl Parameters {
    pub fn new(g0: ECP2, g1: ECP2, h0: ECP2, h1: ECP2) -> Self {
        Parameters { g0, g1, h0, h1 }
    }

    pub fn random() -> Self {
        todo!("not implemented yet");
    }

    pub fn debug(rng: &mut RAND) -> Self {
        print!("this is just debug mode and insecure, do not use it in production");

        Self {
            g0: ECP2::generator().mul(&Big::random(rng)),
            g1: ECP2::generator().mul(&Big::random(rng)),
            h0: ECP2::generator().mul(&Big::random(rng)),
            h1: ECP2::generator().mul(&Big::random(rng)),
        }
    }
}
