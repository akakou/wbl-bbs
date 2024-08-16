use snowbridge_amcl::bls381::ecp2::ECP2;

pub struct Statement {
    pub f: Vec<Vec<ECP2>>,
    pub x: Vec<ECP2>,
}

impl Statement {
    pub fn new(f: Vec<Vec<ECP2>>, x: Vec<ECP2>) -> Self {
        Statement {
            f: f,
            x: x,
        }
    }

    pub fn well_formed(&self) -> Result<(), ()> {
        let rowlen = self.f[0].len();

        for row in self.f.iter() {
            if row.len() != rowlen {
                return Err(())
            }
        }
        
        if self.x.len() != self.f.len() {
            return Err(())
        }

        return Ok(())
    }
}


