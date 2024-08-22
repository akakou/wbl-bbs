use snowbridge_amcl::rand::RAND;

use crate::{
    bound,
    token::{error::TokenProofError, param::Parameters},
};

use super::bbs::{BBSShowing, BBSShowingSecret};

pub struct BoundShowing {
    pub bound: crate::bound::proof::Proof,
}

impl BoundShowing {
    pub fn new(bound: crate::bound::proof::Proof) -> Self {
        Self { bound }
    }

    pub fn show(
        bbs_showing: &BBSShowing,
        secret: &BBSShowingSecret,
        bit_limit: u8,
        params: &Parameters,
        rng: &mut RAND,
    ) -> Result<Self, TokenProofError> {
        let proof = bound::proof::Proof::prove(
            &bbs_showing.k_commit,
            &bound::Parameters {
                g: params.h0.clone(),
                h: params.h1.clone(),
            },
            &bound::Opening {
                k: secret.k_sc.clone(),
                r: secret.k_open.clone(),
            },
            bit_limit as usize,
            rng,
        );

        match proof {
            Ok(proof) => Ok(Self::new(proof)),
            Err(e) => Err(TokenProofError::BoundProofError(e)),
        }
    }

    pub fn verify(
        &self,
        bbs_showing: &BBSShowing,
        bit_limit: u8,
        params: &Parameters,
    ) -> Result<(), TokenProofError> {
        match self.bound.verify(
            &bbs_showing.k_commit,
            &bound::Parameters {
                g: params.h0.clone(),
                h: params.h1.clone(),
            },
            bit_limit as usize,
        ) {
            Ok(_) => Ok(()),
            Err(e) => Err(TokenProofError::BoundProofError(e)),
        }
    }
}
