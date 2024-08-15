
use proof::Proof;
use snowbridge_amcl::{bls381::{big::Big, ecp2::ECP2}, rand::RAND};
use statement::Statement;
use witeness::Witness;

use super::*;

#[test]
fn test_schnorr() {
    let mut rng = RAND::new();
    let seed = vec![0 as u8, 1,2,3,4,5,6,7,8,9];
    rng.seed(10, &seed);


    let x = Big::random(&mut rng);
    let g = ECP2::generator();
    let a = g.mul(&x);

    let statement = Statement::new(
        vec![
            vec![
                g
            ],
        ],
        vec![
            a
        ],
    );

    let witness = Witness(vec![
        x,
    ]);

    let proof = Proof::prove(&statement, &witness, &mut rng);
    let res = Proof::verify(&statement, &proof);

    res.expect("verification failed")

}