use snowbridge_amcl::bls381::{bls381::utils::hash_to_curve_g2, ecp2::ECP2};

pub struct Parameters {
    pub g0: ECP2,
    pub g1: ECP2,
    pub h0: ECP2,
    pub h1: ECP2,
}

impl Parameters {
    pub fn new(g0: ECP2, g1: ECP2, h0: ECP2, h1: ECP2) -> Self {
        Parameters { g0, g1, h0, h1 }
    }

    pub fn default() -> Self {
        let res = Self::new(
            hash_to_curve_g2(b"g0", b"demo"),
            hash_to_curve_g2(b"g1", b"demo"),
            hash_to_curve_g2(b"h0", b"demo"),
            hash_to_curve_g2(b"h1", b"demo"),
        );

        return res;
    }
}
