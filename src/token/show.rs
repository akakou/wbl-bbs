use core::panic;

use snowbridge_amcl::{
    bls381::{big::Big, ecp::ECP, ecp2::ECP2, pair},
    rand::RAND,
};

use crate::{
    bound,
    linear::{self, utils::order},
};

use super::{keygen::PublicKey, param::Parameters, token::Token};

pub struct BBSShowing {
    pub aprime: ECP2,
    pub abar: ECP2,
    pub d: ECP2,
    // pub attributes: Vec<ECP2>,
    pub tiket: ECP2,
    pub commit: ECP2,
}

impl BBSShowing {
    pub fn show(
        token: &Token,
        origins: &ECP2,
        k: u8,
        params: &Parameters,
        rng: &mut RAND,
    ) -> Result<Self, ()> {
        if k == 0 {
            return Err(());
        }

        let r1 = Big::random(rng);
        let aprime = token.a.mul(&r1);
        let commit: ECP2 = token.compute_commit_from_token(params);

        let mut tmp0 = token.a.mul(&token.e);
        tmp0.neg();
        tmp0.add(&commit);

        let abar = tmp0.mul(&r1);

        let r2 = Big::random(rng);

        let mut d = commit.mul(&r1);

        let neg_r2 = Big::modneg(&r2, &order());
        let tmp = params.g1.mul(&neg_r2);
        d.add(&tmp);

        let k_open = Big::random(rng);
        let k_sc = Big::new_int(k as isize);

        let mut k_comm = params.h0.mul(&k_sc);
        let tmp1 = params.h1.mul(&k_open);
        k_comm.add(&tmp1);

        let mut origin_exp = k_sc.clone();
        origin_exp.add(&token.key);
        origin_exp.invmodp(&order());

        let ticket = origins.mul(&origin_exp);

        return Ok(Self {
            aprime,
            abar,
            d,
            // attributes:
            tiket: ticket,
            commit,
        });
    }

    pub fn verify(&self, pk: &PublicKey) -> Result<(), ()> {
        if self.aprime.equals(&ECP2::new()) {
            return Err(());
        }

        let mut left = pair::ate(&self.aprime, &pk.0);
        left = pair::fexp(&left);

        let mut right = pair::ate(&self.abar, &ECP::generator());
        right = pair::fexp(&right);

        if left.equals(&right) {
            return Ok(());
        } else {
            return Err(());
        }
    }
}
