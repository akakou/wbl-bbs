
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

    let g0 = ECP2::generator().mul(&Big::random(&mut rng));
    let g1 = ECP2::generator().mul(&Big::random(&mut rng));

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

#[test]
fn test_commit_eq() {
    let mut rng = RAND::new();
    let seed = vec![0 as u8, 1,2,3,4,5,6,7,8,9];
    rng.seed(10, &seed);

    let x = Big::random(&mut rng);
    let r0 = Big::random(&mut rng);
    let r1 = Big::random(&mut rng);

    let g0 = ECP2::generator().mul(&Big::random(&mut rng));
    let g1 = ECP2::generator().mul(&Big::random(&mut rng));
    
    let h0 = ECP2::generator().mul(&Big::random(&mut rng));
    let h1 = ECP2::generator().mul(&Big::random(&mut rng));

    let mut c0 = g0.mul(&x);
    let tmp0 = h0.mul(&r0);
    c0.add(&tmp0);

    let mut c1 = g1.mul(&x);
    let tmp1 = h1.mul(&r1);
    c1.add(&tmp1);

    let statement = Statement::new(
        vec![
            vec![
                g0, h0, ECP2::new(), 
            ],
            vec![
                g1, ECP2::new(), h1,
            ],
        ],
        vec![
            c0, c1
        ],
    );

    let witness = Witness(vec![
        x, r0, r1,
    ]);

    let proof = Proof::prove(&statement, &witness, &mut rng).expect("proving failed");
    let res = Proof::verify(&statement, &proof);

    res.expect("verification failed")
}