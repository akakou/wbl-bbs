use snowbridge_amcl::bls381::ecp2::ECP2;

use super::error::LinerProofError;

pub struct Statement {
    pub f: Vec<Vec<ECP2>>,
    pub x: Vec<ECP2>,
}

impl Statement {
    pub fn new(f: Vec<Vec<ECP2>>, x: Vec<ECP2>) -> Self {
        Statement {f,x}
    }

    pub fn well_formed(&self) -> Result<(), LinerProofError> {
        let rowlen = self.f[0].len();

        for (i, row) in self.f.iter().enumerate() {
            if row.len() != rowlen {
                return Err(LinerProofError::StatementFNotWellFormed(row.len(), rowlen, i))
            }
        }
        
        if self.x.len() != self.f.len() {
            return Err(LinerProofError::StatementNotWellFormed(self.x.len(), self.f.len()))
        }

        return Ok(())
    }
}


