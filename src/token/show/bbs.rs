use snowbridge_amcl::{
    bls381::{big::Big, ecp::ECP, ecp2::ECP2, pair},
    rand::RAND,
};

use crate::{
    linear::utils::order,
    token::{error::TokenProofError, keygen::PublicKey, param::Parameters, token::Token},
};

pub struct BBSShowing {
    pub aprime: ECP2,
    pub abar: ECP2,
    pub d: ECP2,
    // pub attributes: Vec<ECP2>,
    pub ticket: ECP2,
    pub commit: ECP2,
    pub k_commit: ECP2,
}

pub struct BBSShowingSecret {
    pub k_open: Big,
    pub k_sc: Big,
    pub r1: Big,
    pub r2: Big,
}

impl BBSShowing {
    pub fn show(
        token: &Token,
        origins: &ECP2,
        k: u8,
        params: &Parameters,
        rng: &mut RAND,
    ) -> Result<(Self, BBSShowingSecret), TokenProofError> {
        if k == 0 {
            return Err(TokenProofError::InvalidZeroBitLimit);
        }

        let r1 = Big::random(rng);
        let aprime = token.a.mul(&r1);
        let commit = token.compute_commit_from_token(params);

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

        let mut k_commit = params.h0.mul(&k_sc);
        let tmp1 = params.h1.mul(&k_open);
        k_commit.add(&tmp1);

        let mut origin_exp = k_sc.clone();
        origin_exp.add(&token.key);
        origin_exp.invmodp(&order());

        let ticket = origins.mul(&origin_exp);

        return Ok((
            Self {
                aprime,
                abar,
                d,
                // attributes:
                ticket,
                k_commit,
                commit,
            },
            BBSShowingSecret {
                k_open,
                k_sc,
                r1,
                r2,
            },
        ));
    }

    pub fn verify(&self, pk: &PublicKey) -> Result<(), TokenProofError> {
        if self.aprime.equals(&ECP2::new()) {
            return Err(TokenProofError::APrimeIsUnity);
        }

        let mut left = pair::ate(&self.aprime, &pk.0);
        left = pair::fexp(&left);

        let mut right = pair::ate(&self.abar, &ECP::generator());
        right = pair::fexp(&right);

        if left.equals(&right) {
            return Ok(());
        } else {
            return Err(TokenProofError::PairingCheckFailedInShowing(
                left.to_string(),
                right.to_string(),
            ));
        }
    }
}
