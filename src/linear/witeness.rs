use snowbridge_amcl::bls381::{big::Big, ecp2::ECP2};

use super::{error::LinearProofError, statement::Statement, utils::calc_inner_product};

pub struct Witness(pub Vec<Big>);

impl Witness {
    pub fn new(input: usize) -> Self {
        Witness(vec![Big::new(); input])
    }

    pub fn well_formed(&self, statement: &Statement) -> Result<(), LinearProofError> {
        if self.0.len() == statement.f[0].len() {
            return Ok(());
        } else {
            return Err(LinearProofError::WitnessNotWellFormed(
                self.0.len(),
                statement.f[0].len(),
            ));
        }
    }

    pub fn satisfied(&self, statement: &Statement) -> Result<(), LinearProofError> {
        self.well_formed(statement)?;

        for (i, f) in statement.f.iter().enumerate() {
            let x = calc_inner_product(f, &self.0);
            if !x.equals(&statement.x[i]) {
                return Err(LinearProofError::WitnessNotSatisfied(x.to_string(), statement.x[i].to_string(), i));
            }
        }

        return Ok(());
    }
}
