pub mod error;
pub mod proof;

use snowbridge_amcl::bls381::{big::Big, ecp2::ECP2};

pub struct Parameters {
    pub g: ECP2,
    pub h: ECP2,
}

pub struct Opening {
    pub k: Big,
    pub r: Big,
}

const MAX_BIT_LENGTH: usize = 8;

#[cfg(test)]
mod test;
