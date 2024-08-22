use snowbridge_amcl::{
    bls381::{big::Big, ecp2::ECP2},
    rand::RAND,
};

use crate::utils::{self, order};

use crate::{
    linear::{self, statement::Statement, witeness::Witness},
    token::{error::TokenProofError, param::Parameters, token::Token},
};

use super::{
    bbs::{BBSShowing, BBSShowingSession},
    core::{CoreShowing, CoreShowingSession},
};

pub struct LinearShowing {
    pub linear: linear::proof::Proof,
    pub d: ECP2,
}

impl LinearShowing {
    pub fn new(d: ECP2, linear: linear::proof::Proof) -> Self {
        Self { d, linear }
    }

    pub fn show(
        token: &Token,
        origin: &ECP2,
        core_showing: &CoreShowing,
        core_session: &CoreShowingSession,
        bbs_showing: &BBSShowing,
        bbs_session: &BBSShowingSession,
        params: &Parameters,
        rng: &mut RAND,
    ) -> Result<Self, TokenProofError> {
        let r2 = Big::random(rng);

        let mut d = bbs_session.commit.mul(&bbs_session.r1);

        let neg_r2 = Big::modneg(&r2, &order());
        let tmp = params.g1.mul(&neg_r2);
        d.add(&tmp);

        let mut r3 = bbs_session.r1.clone();
        r3.invmodp(&order());

        let mut sprime = Big::modmul(&r2, &r3, &order());
        sprime = Big::modneg(&sprime, &order());
        sprime.add(&token.s);

        let witness = Witness(vec![
            Big::modneg(&token.e, &order()),
            r2.clone(),
            r3,
            Big::modneg(&sprime, &order()),
            token.key.clone(),
            core_session.k_sc.clone(),
            core_session.k_open.clone(),
        ]);

        let stmt = Self::stmt(&d, core_showing, bbs_showing, origin, params);

        let linear = linear::proof::Proof::prove(&stmt, &witness, rng).expect("prove failed");
        // witness.satisfied(&stmt).expect("witness not satisfied");

        return Ok(Self::new(d, linear));
    }

    fn stmt(
        d: &ECP2,
        core_showing: &CoreShowing,
        bbs_showing: &BBSShowing,
        origin: &ECP2,
        params: &Parameters,
    ) -> Statement {
        let mut neg_h0 = params.h0.clone();
        neg_h0.neg();

        let mut x0 = d.clone();
        x0.neg();
        x0.add(&bbs_showing.abar);

        let mut x1 = params.h1.mul(&utils::hash(&core_showing.attribute));
        x1.add(&params.g0);

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
                    d.clone(),
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
                    core_showing.ticket.clone(),
                    core_showing.ticket.clone(),
                    ECP2::new(),
                ],
            ],
            vec![x0, x1, core_showing.k_commit.clone(), origin.clone()],
        );

        // stmt.well_formed().expect("stmt not well formed");
        return stmt;
    }

    pub fn verify(
        &self,
        core_showing: &CoreShowing,
        bbs_showing: &BBSShowing,
        origin: &ECP2,
        params: &Parameters,
    ) -> Result<(), TokenProofError> {
        let stmt = Self::stmt(&self.d, core_showing, bbs_showing, origin, params);

        match self.linear.verify(&stmt) {
            Ok(_) => Ok(()),
            Err(e) => Err(TokenProofError::LinearProofError(e)),
        }
    }
}
