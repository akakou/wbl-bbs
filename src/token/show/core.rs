use snowbridge_amcl::{
    bls381::{big::Big, ecp2::ECP2},
    rand::RAND,
};

use crate::{
    token::{error::TokenProofError, param::Parameters, token::Token},
    utils::order,
};

pub struct CoreShowing {
    pub ticket: ECP2,
    pub k_commit: ECP2,
}

pub struct CoreShowingSession {
    pub k_open: Big,
    pub k_sc: Big,
}

impl CoreShowing {
    pub fn show(
        token: &Token,
        origins: &ECP2,
        bit_limit: u8,
        params: &Parameters,
        rng: &mut RAND,
    ) -> Result<(Self, CoreShowingSession), TokenProofError> {
        let k_open = Big::random(rng);
        let k_sc = Big::new_int(bit_limit as isize);

        let mut k_commit = params.h0.mul(&k_sc);
        let tmp1 = params.h1.mul(&k_open);
        k_commit.add(&tmp1);

        let mut origin_exp = k_sc.clone();
        origin_exp.add(&token.key);
        origin_exp.invmodp(&order());

        let ticket = origins.mul(&origin_exp);

        return Ok((
            Self { ticket, k_commit },
            CoreShowingSession { k_open, k_sc },
        ));
    }
}
