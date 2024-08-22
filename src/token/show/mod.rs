use core::CoreShowing;

use snowbridge_amcl::{
    bls381::{bls381::utils::hash_to_curve_g2, ecp2::ECP2},
    rand::RAND,
};

use super::{error::TokenProofError, keygen::PublicKey, param::Parameters, token::Token};

pub mod bbs;
pub mod bound;
pub mod core;
pub mod linear;

pub struct Showing {
    pub linear: linear::LinearShowing,
    pub bound: bound::BoundShowing,
    pub bbs: bbs::BBSShowing,
    pub core: CoreShowing,
}

impl Showing {
    pub fn new(
        linear: linear::LinearShowing,
        bound: bound::BoundShowing,
        bbs: bbs::BBSShowing,
        core: CoreShowing,
    ) -> Self {
        Self {
            linear,
            bound,
            bbs,
            core,
        }
    }

    pub fn show(
        token: &Token,
        origin: &[u8],
        bit_limit: u8,
        params: &Parameters,
        rng: &mut RAND,
    ) -> Result<Self, TokenProofError> {
        let origin = hash_to_curve_g2(origin, b"origin generator");

        let (core_showing, core_session) =
            core::CoreShowing::show(token, &origin, bit_limit, &token.attribute, params, rng)?;
        let (bbs_showing, bbs_session) = bbs::BBSShowing::show(token, bit_limit, params, rng)?;

        let bound =
            bound::BoundShowing::show(bit_limit, &core_showing, &core_session, params, rng)?;
        let linear = linear::LinearShowing::show(
            &token,
            &origin,
            &core_showing,
            &core_session,
            &bbs_showing,
            &bbs_session,
            params,
            rng,
        )?;

        return Ok(Self::new(linear, bound, bbs_showing, core_showing));
    }

    pub fn verify(
        &self,
        bit_limit: u8,
        origin: &[u8],
        pk: &PublicKey,
        params: &Parameters,
    ) -> Result<(), TokenProofError> {
        let origin = hash_to_curve_g2(origin, b"origin generator");

        self.bbs.verify(pk)?;
        self.bound.verify(&self.core, bit_limit, &params)?;
        self.linear
            .verify(&self.core, &self.bbs, &origin, &params)?;
        Ok(())
    }
}
