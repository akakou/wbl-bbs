use snowbridge_amcl::{
    bls381::{big::Big, ecp::ECP, ecp2::ECP2, pair},
    rand::RAND,
};

use crate::linear::utils::order;

use super::{
    error::TokenProofError,
    keygen::{PublicKey, SigningKey},
    param::Parameters,
};

pub struct Token {
    pub a: ECP2,
    pub e: Big,
    pub s: Big,
    pub key: Big,
    pub attribute: Vec<u8>,
    pub debug_u: ECP2,
}

pub struct PreToken {
    pub s: Big,
    pub x: Big,
    pub attribute: Vec<u8>,
}

impl Token {
    pub fn new(a: ECP2, e: Big, s: Big, key: Big, attribute: Vec<u8>) -> Self {
        Token {
            a,
            e,
            s,
            key,
            attribute,
            debug_u: ECP2::new(),
        }
    }

    pub fn make(attribute: Vec<u8>, sk: &SigningKey, params: &Parameters, rng: &mut RAND) -> Self {
        let attr = Big::new();
        let key = Big::random(rng);

        let mut u = params.h0.mul(&key);
        let tmp0 = params.h1.mul(&attr);
        u.add(&tmp0);

        let s = Big::random(rng);
        let tmp1 = params.g1.mul(&s);
        u.add(&tmp1);
        u.add(&params.g0);

        let e = Big::random(rng);
        let mut exp = e.clone();
        exp.add(&sk.0);
        exp.invmodp(&order());

        let a = u.mul(&exp);

        Token {
            a,
            e,
            s,
            key,
            attribute,
            debug_u: u,
        }
    }

    pub(crate) fn compute_commit_from_token(&self, params: &Parameters) -> ECP2 {
        let mut commit = params.h0.mul(&self.key);

        let attr = Big::new();

        let tmp0 = params.h1.mul(&attr);
        commit.add(&tmp0);

        let tmp1 = params.g1.mul(&self.s);
        commit.add(&tmp1);
        commit.add(&params.g0);

        return commit;
    }

    pub fn verify(&self, pub_key: &PublicKey, params: &Parameters) -> Result<(), TokenProofError> {
        let commit = self.compute_commit_from_token(params);

        if !commit.equals(&self.debug_u) {
            return Err(TokenProofError::CommitCheckFailed(
                commit.to_string(),
                self.debug_u.to_string(),
            ));
        }

        let mut key_adj = ECP::generator().mul(&self.e);
        key_adj.add(&pub_key.0);

        let mut left = pair::ate(&self.a, &key_adj);
        left = pair::fexp(&left);

        let mut right = pair::ate(&commit, &ECP::generator());
        right = pair::fexp(&right);

        if !left.equals(&right) {
            return Err(TokenProofError::PairingCheckFailedInToken(
                left.to_string(),
                right.to_string(),
            ));
        }

        return Ok(());
    }
}
