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
}


