use snowbridge_amcl::{
    bls381::{big::Big, ecp2::ECP2},
    rand::RAND,
};

use super::{proof::Proof, Opening, Parameters};

#[test]
fn test_bound_proof() {
    let mut rng = RAND::new();
    let seed = vec![0 as u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    rng.seed(10, &seed);

    let params = Parameters {
        g: ECP2::generator().mul(&Big::random(&mut rng)),
        h: ECP2::generator().mul(&Big::random(&mut rng)),
    };

    let open = Opening {
        k: Big::new_int(5),
        r: Big::random(&mut rng),
    };

    let mut comm = params.g.mul(&open.k);
    let tmp = params.h.mul(&open.r);
    comm.add(&tmp);

    let proof = Proof::prove(&comm, &params, &open, 3, &mut rng).expect("proving failed");
    let res = proof.verify(&comm, &params, 3);

    res.expect("verification failed")
}
