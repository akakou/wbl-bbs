use snowbridge_amcl::rand::RAND;

use super::{
    keygen::{PublicKey, SigningKey},
    param::Parameters,
    show::Showing,
    token::Token,
};

#[test]
fn test_make_token() {
    let mut rng = RAND::new();
    let seed = vec![0 as u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    rng.seed(10, &seed);

    let sk = SigningKey::random(&mut rng);
    let pk = PublicKey::from_signing_key(&sk);

    let params = Parameters::default();

    let t = Token::make(vec![1, 2, 3], &sk, &params, &mut rng);
    let res = t.verify(&pk, &params);
    res.expect("verification failed");
}

#[test]
fn test_showing() {
    let mut rng = RAND::new();
    let seed = vec![0 as u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    rng.seed(10, &seed);

    let sk = SigningKey::random(&mut rng);
    let pk = PublicKey::from_signing_key(&sk);

    let params = Parameters::default();
    let t = Token::make(vec![1, 2, 3], &sk, &params, &mut rng);

    let showing = Showing::show(&t, b"hello", 3, &params, &mut rng).expect("showing failed");
    showing
        .verify(3, b"hello", &pk, &params)
        .expect("verification failed");
}
