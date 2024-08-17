use snowbridge_amcl::bls381::{big::Big, ecp::ECP, ecp2::ECP2};

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

pub struct Token {
    pub a: ECP2,
    pub e: Big,
    pub s: Big,
    pub key: Big,
    pub attribute: Vec<u8>,
}

pub struct PreToken {
    pub s: Big,
    pub x: Big,
    pub attribute: Vec<u8>,
}

pub struct Signature {
    pub a: ECP2,
    pub sprime: Big,
    pub e: Big,
}


pub struct Parameters {
    pub g0: ECP2,
    pub g1: ECP2,
    pub h0: ECP2,
    pub h1: ECP2,
}

pub mod keygen;