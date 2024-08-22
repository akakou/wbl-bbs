use snowbridge_amcl::{bls381::{big::Big, ecp2::ECP2}, rand::RAND};

use crate::{linear::{self, statement::Statement, utils::order, witeness::Witness}, token::{error::TokenProofError, param::Parameters, token::Token}};

use super::bbs::{BBSShowing, BBSShowingSecret};


pub struct LinearShowing {
    pub linear: linear::proof::Proof,
}

impl LinearShowing {
    pub fn new(linear: linear::proof::Proof) -> Self {
        Self { linear: linear }
    }

    pub fn show(
        bbs: &BBSShowing,
        secret: &BBSShowingSecret,
        token: &Token,
        origin: &ECP2,
        params: &Parameters,
        rng: &mut RAND,
    ) -> Result<Self, TokenProofError> {
        let mut r3 = secret.r1.clone();
        r3.invmodp(&order());

        let mut sprime = Big::modmul(&secret.r2, &r3, &order());
        sprime = Big::modneg(&sprime, &order());
        sprime.add(&token.s);

        let witness = Witness(vec![
            Big::modneg(&token.e, &order()),
            secret.r2.clone(),
            r3,
            Big::modneg(&sprime, &order()),
            token.key.clone(),
            secret.k_sc.clone(),
            secret.k_open.clone(),
        ]);

        let stmt = Self::stmt(bbs, origin, params);

        let linear = linear::proof::Proof::prove(&stmt, &witness, rng).expect("prove failed");
        // witness.satisfied(&stmt).expect("witness not satisfied");

        return Ok(Self::new(linear));
    }

    fn stmt(bbs_showing: &BBSShowing, origin: &ECP2, params: &Parameters) -> Statement {
        let mut neg_h0 = params.h0.clone();
        neg_h0.neg();

        let mut x0 = bbs_showing.d.clone();
        x0.neg();
        x0.add(&bbs_showing.abar);

        let mut x1 = params.g0.clone();
        x1.add(&ECP2::new());

        let stmt = Statement::new(
            vec![
                vec![
                    bbs_showing.aprime.clone(),
                    params.g1.clone(),
                    ECP2::new(),
                    ECP2::new(),
                    ECP2::new(),
                    ECP2::new(),
                    ECP2::new(),
                ],
                vec![
                    ECP2::new(),
                    ECP2::new(),
                    bbs_showing.d.clone(),
                    params.g1.clone(),
                    neg_h0,
                    ECP2::new(),
                    ECP2::new(),
                ],
                vec![
                    ECP2::new(),
                    ECP2::new(),
                    ECP2::new(),
                    ECP2::new(),
                    ECP2::new(),
                    params.h0.clone(),
                    params.h1.clone(),
                ],
                vec![
                    ECP2::new(),
                    ECP2::new(),
                    ECP2::new(),
                    ECP2::new(),
                    bbs_showing.ticket.clone(),
                    bbs_showing.ticket.clone(),
                    ECP2::new(),
                ],
            ],
            vec![x0, x1, bbs_showing.k_commit.clone(), origin.clone()],
        );

        // stmt.well_formed().expect("stmt not well formed");
        return stmt;
    }

    pub fn verify(
        &self,
        bbs_showing: &BBSShowing,
        origin: &ECP2,
        params: &Parameters,
    ) -> Result<(), TokenProofError> {
        let stmt = Self::stmt(bbs_showing, origin, params);

        match self.linear.verify(&stmt) {
            Ok(_) => Ok(()),
            Err(e) => Err(TokenProofError::LinearProofError(e)),
        }
    }
}
