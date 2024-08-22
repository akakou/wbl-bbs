use snowbridge_amcl::{
    bls381::{big::Big, ecp::ECP, ecp2::ECP2, pair},
    rand::RAND,
};

use crate::token::{error::TokenProofError, keygen::PublicKey, param::Parameters, token::Token};

pub struct BBSShowing {
    pub aprime: ECP2,
    pub abar: ECP2,
}

pub struct BBSShowingSession {
    pub commit: ECP2,
    pub r1: Big,
}

impl BBSShowing {
    pub fn show(
        token: &Token,
        k: u8,
        params: &Parameters,
        rng: &mut RAND,
    ) -> Result<(Self, BBSShowingSession), TokenProofError> {
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
        return Ok((Self { aprime, abar }, BBSShowingSession { commit, r1 }));
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
