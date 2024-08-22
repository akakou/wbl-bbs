use snowbridge_amcl::rand::RAND;

use crate::{
    bound,
    token::{error::TokenProofError, param::Parameters},
};

use super::core::{CoreShowingSession, CoreShowing};

pub struct BoundShowing {
    pub bound: crate::bound::proof::Proof,
}

impl BoundShowing {
    pub fn new(bound: crate::bound::proof::Proof) -> Self {
        Self { bound }
    }

    pub fn show(
        bit_limit: u8,
        core_showing: &CoreShowing,
        core_session: &CoreShowingSession,
        params: &Parameters,
        rng: &mut RAND,
    ) -> Result<Self, TokenProofError> {
        let proof = bound::proof::Proof::prove(
            &core_showing.k_commit,
            &bound::Parameters {
                g: params.h0.clone(),
                h: params.h1.clone(),
            },
            &bound::Opening {
                k: core_session.k_sc.clone(),
                r: core_session.k_open.clone(),
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
        core_showing: &CoreShowing,
        bit_limit: u8,
        params: &Parameters,
    ) -> Result<(), TokenProofError> {
        match self.bound.verify(
            &core_showing.k_commit,
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
