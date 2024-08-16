
use std::vec;

use proof::Proof;
use snowbridge_amcl::{bls381::{big::Big, ecp2::ECP2, hash_to_curve::{self, hash, HashAlgorithm}, mpin::SHA256}, rand::RAND};
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

    let proof = Proof::prove(&statement, &witness, &mut rng).expect("proving failed");
    let res = Proof::verify(&statement, &proof);

    res.expect("verification failed")

}


#[test]
fn test_dlog() {
    let mut rng = RAND::new();
    let seed = vec![0 as u8, 1,2,3,4,5,6,7,8,9];
    rng.seed(10, &seed);

    let x = Big::random(&mut rng);

    let g0 = ECP2::generator();
    let g1 = ECP2::generator().mul(&Big::new_int(2));

    let b0 = g0.mul(&x);
    let b1 = g1.mul(&x);

    let statement = Statement::new(
        vec![
            vec![
                g0,
            ],
            vec![
                g1,
            ]
        ],
        vec![
            b0, b1
        ],
    );


    let witness = Witness(vec![
        x,
    ]);

    let proof = Proof::prove(&statement, &witness, &mut rng).expect("proving failed");
    let res = Proof::verify(&statement, &proof);

    res.expect("verification failed")
    
}