use snowbridge_amcl::{
    bls381::{big::Big, ecp::ECP, ecp2::ECP2, pair},
    rand::RAND,
};

use super::{
    keygen::{PublicKey, SigningKey},
    param::Parameters,
    show::{BBSShowing, BoundShowing, LinearShowing},
    token::{self, Token},
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

    let (bbs_showing, bbs_secret) =
        BBSShowing::show(&t, &ECP2::generator(), 3, &params, &mut rng).expect("showing failed");
    let bound = BoundShowing::show(&bbs_showing, &bbs_secret, 3, &params, &mut rng)
        .expect("showing failed");

    bound
        .verify(&bbs_showing, 3, &params)
        .expect("verification failed");
}

#[test]
fn test_linear_showing() {
    let mut rng = RAND::new();
    let seed = vec![0 as u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    rng.seed(10, &seed);

    let sk = SigningKey::random(&mut rng);
    let pk = PublicKey::from_signing_key(&sk);

    let params = Parameters::debug(&mut rng);
    let t = Token::make(vec![1, 2, 3], &sk, &params, &mut rng);

    let (bbs_showing, bbs_secret) =
        BBSShowing::show(&t, &ECP2::generator(), 3, &params, &mut rng).expect("showing failed");
    let linear = LinearShowing::show(
        &bbs_showing,
        &bbs_secret,
        &t,
        &ECP2::generator(),
        &params,
        &mut rng,
    )
    .expect("showing failed");
    linear
        .verify(&bbs_showing, &ECP2::generator(), &params)
        .expect("verification failed");
}
