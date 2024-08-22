use snowbridge_amcl::{bls381::ecp2::ECP2, rand::RAND};

use super::{error::TokenProofError, keygen::PublicKey, param::Parameters, token::Token};

pub mod bbs;
pub mod bound;
pub mod linear;

pub struct Showing {
    pub linear: linear::LinearShowing,
    pub bound: bound::BoundShowing,
    pub bbs: bbs::BBSShowing,
}

impl Showing {
    pub fn new(
        linear: linear::LinearShowing,
        bound: bound::BoundShowing,
        bbs: bbs::BBSShowing,
    ) -> Self {
        Self { linear, bound, bbs }
    }

    pub fn show(
        t: &Token,
        origin: &ECP2,
        bit_limit: u8,
        params: &Parameters,
        rng: &mut RAND,
    ) -> Result<Self, TokenProofError> {
        let (bbs_showing, bbs_secret) = bbs::BBSShowing::show(t, origin, bit_limit, params, rng)?;
        let bound = bound::BoundShowing::show(&bbs_showing, &bbs_secret, bit_limit, params, rng)?;
        let linear =
            linear::LinearShowing::show(&bbs_showing, &bbs_secret, t, origin, params, rng)?;

        return Ok(Self::new(linear, bound, bbs_showing));
    }

    pub fn verify(
        &self,
        bit_limit: u8,
        origin: &ECP2,
        pk: &PublicKey,
        params: &Parameters,
    ) -> Result<(), TokenProofError> {
        self.bbs.verify(pk)?;
        self.bound.verify(&self.bbs, bit_limit, &params)?;
        self.linear.verify(&self.bbs, &origin, &params)?;

        Ok(())
    }
}
