use blake2::{Blake2s256, Digest};
use snowbridge_amcl::bls381::{big::Big, ecp2::ECP2, rom};

use super::{proof::Proof, statement::Statement};

pub(crate) fn hash(statement: &Statement, proof: &Proof) -> Big {
    let mut hash = Blake2s256::new();
    let mut buf = [0u8; rom::MODBYTES*4];

    for row in statement.f.iter() {
        for elt in row {
            elt.to_bytes(&mut buf);
            hash.update(buf);

        }
    }

    for x in statement.x.iter() {
        x.to_bytes(&mut buf);
        hash.update(buf);
    }

    for r in proof.r.iter(){
        r.to_bytes(&mut buf);
        hash.update(buf);
    }

    let h = hash.finalize();
    let c = Big::from_bytes(&h);

    return c;
}



// base * multer + adder
pub(crate) fn calc_sigma_response(base: &Big, multer: &Big, adder: &Big) -> Big {
    let mut res = Big::modmul(base, multer, &order());
    res.add(adder);

    return res;
}

// base * multer + adder
pub(crate) fn calc_inner_product_one(base: &ECP2, multer: &Big, adder: &ECP2) -> ECP2 {
    let mut res = base.mul(&multer);
    res.add(adder);

    return res
}

// base_1 * multer_1 + base_2 * multer_2 + ... + base_n * multer_n 
pub(crate) fn calc_inner_product(base: &[ECP2], multers: &[Big]) -> ECP2 {
    let mut res = ECP2::new();

    if base.len() != multers.len() {
        panic!("{} != {}", base.len(), multers.len())
    } 

    for i in 0..multers.len(){
        let t = calc_inner_product_one(&base[i], &multers[i], &res);
        res.add(&t);
    }

    return res;
}


pub(crate) fn order() -> Big {
    Big::new_ints(&rom::CURVE_ORDER)
}
