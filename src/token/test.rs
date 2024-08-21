use snowbridge_amcl::{
    bls381::{big::Big, ecp::ECP, ecp2::ECP2, pair},
    rand::RAND,
};

use super::{
    keygen::{PublicKey, SigningKey},
    param::Parameters,
    show::{BBSShowing, BoundShowing},
    token::Token,
};

#[test]
fn test_make_token() {
    let mut rng = RAND::new();
    let seed = vec![0 as u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    rng.seed(10, &seed);

    let sk = SigningKey::random(&mut rng);
    let pk = PublicKey::from_signing_key(&sk);

    let params = Parameters::debug(&mut rng);

    let t = Token::make(vec![1, 2, 3], &sk, &params, &mut rng);
    let res = t.verify(&pk, &params);
    res.expect("verification failed");
}

#[test]
fn test_bbs_showing() {
    let mut rng = RAND::new();
    let seed = vec![0 as u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    rng.seed(10, &seed);

    let sk = SigningKey::random(&mut rng);
    let pk = PublicKey::from_signing_key(&sk);

    let params = Parameters::debug(&mut rng);
    let t = Token::make(vec![1, 2, 3], &sk, &params, &mut rng);

    let (s, _) =
        BBSShowing::show(&t, &ECP2::generator(), 3, &params, &mut rng).expect("showing failed");

    s.verify(&pk).expect("verification failed");
}

#[test]
fn test_bound_showing() {
    let mut rng = RAND::new();
    let seed = vec![0 as u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    rng.seed(10, &seed);

    let sk = SigningKey::random(&mut rng);
    let pk = PublicKey::from_signing_key(&sk);

    let params = Parameters::debug(&mut rng);
    let t = Token::make(vec![1, 2, 3], &sk, &params, &mut rng);

    let (bbs, secret) =
        BBSShowing::show(&t, &ECP2::generator(), 3, &params, &mut rng).expect("showing failed");
    let bound = BoundShowing::show(&secret, 3, &params, &mut rng).expect("showing failed");

    bound
        .verify(&secret.k_commit, 3, &params)
        .expect("verification failed");
}
