use std::vec;

use snowbridge_amcl::bls381::big::Big;
use snowbridge_amcl::bls381::ecp2::ECP2;
use snowbridge_amcl::rand::RAND;

use super::error::LinearProofError;
use super::statement::Statement;
use super::utils::{self, calc_inner_product, calc_inner_product_one, calc_sigma_response};
use super::witeness::Witness;

pub struct Proof {
    pub r: Vec<ECP2>,
    pub s: Vec<Big>,
}

impl Proof {
    pub fn new(input: usize, output: usize) -> Self {
        Proof {
            r: vec![ECP2::new(); output],
            s: vec![Big::new(); input],
        }
    }

    pub fn prove(
        statement: &Statement,
        witness: &Witness,
        rng: &mut RAND,
    ) -> Result<Self, LinearProofError> {
        statement.well_formed()?;
        witness.well_formed(statement)?;

        let input_len = witness.0.len();
        let output_len = statement.x.len();

        let mut proof = Proof::new(input_len, output_len);

        let randoms = vec![Big::random(rng); input_len];

        for (i, f) in statement.f.iter().enumerate() {
            proof.r[i] = calc_inner_product(f, &randoms);
        }

        let c = utils::hash(statement, &proof);

        for i in 0..proof.s.len() {
            proof.s[i] = calc_sigma_response(&c, &witness.0[i], &randoms[i]);
        }

        return Ok(proof);
    }

    pub fn verify(&self, statement: &Statement) -> Result<(), LinearProofError> {
        let c = utils::hash(statement, self);
        let output_len = statement.x.len();

        for i in 0..output_len {
            let lhs = calc_inner_product(&statement.f[i], &self.s);
            let rhs = calc_inner_product_one(&statement.x[i], &c, &self.r[i]);

            if !lhs.equals(&rhs) {
                return Err(LinearProofError::VerifyFailed(
                    lhs.to_string(),
                    lhs.to_string(),
                    i,
                ));
            }
        }

        return Ok(());
    }
}
