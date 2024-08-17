use snowbridge_amcl::bls381::{big::Big, ecp::ECP, ecp2::ECP2};

use crate::linear;

pub struct Parameters {
    pub g: ECP2,
    pub h: ECP2,
}

pub struct Proof {
    pub ci: Vec<ECP2>,
    pub pi: linear::proof::Proof,
}

pub struct Opening {
    pub k: Big,
    pub r: Big,
}

