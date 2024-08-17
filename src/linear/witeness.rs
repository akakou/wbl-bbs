use snowbridge_amcl::bls381::big::Big;

use super::{error::LinearProofError, statement::Statement};

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
}
