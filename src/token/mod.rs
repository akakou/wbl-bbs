use snowbridge_amcl::bls381::{big::Big, ecp2::ECP2};

use crate::{bound, linear};

pub struct Showing {
    pub aprime: ECP2,
    pub abar: ECP2,
    pub d: ECP2,
    pub attributes: Vec<ECP2>,
    pub tiket: ECP2,
    pub commit: ECP2,
    pub range_proof: bound::proof::Proof,
    pub pi: linear::proof::Proof,
}

pub struct Signature {
    pub a: ECP2,
    pub sprime: Big,
    pub e: Big,
}

pub mod keygen;
pub mod param;
pub mod token;

#[cfg(test)]
pub mod test;
