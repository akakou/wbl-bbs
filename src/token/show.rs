use core::panic;

use snowbridge_amcl::{
    bls381::{big::Big, ecp::ECP, ecp2::ECP2, pair},
    rand::RAND,
};

use crate::{
    bound::{self, error::BoundProofError},
    linear::{self, statement::Statement, utils::order, witeness::Witness},
};

use super::{keygen::PublicKey, param::Parameters, token::Token};

pub struct BBSShowing {
    pub aprime: ECP2,
    pub abar: ECP2,
    pub d: ECP2,
    // pub attributes: Vec<ECP2>,
    pub ticket: ECP2,
    pub commit: ECP2,
    pub k_commit: ECP2,
}

pub struct BBSShowingSecret {
    pub k_open: Big,
    pub k_sc: Big,
    pub r1: Big,
    pub r2: Big,
}

impl BBSShowing {
    pub fn show(
        token: &Token,
        origins: &ECP2,
        k: u8,
        params: &Parameters,
        rng: &mut RAND,
    ) -> Result<(Self, BBSShowingSecret), ()> {
        if k == 0 {
            return Err(());
        }

        let r1 = Big::random(rng);
        let aprime = token.a.mul(&r1);
        let commit = token.compute_commit_from_token(params);

        let mut tmp0 = token.a.mul(&token.e);
        tmp0.neg();
        tmp0.add(&commit);

        let abar = tmp0.mul(&r1);

        let r2 = Big::random(rng);

        let mut d = commit.mul(&r1);

        let neg_r2 = Big::modneg(&r2, &order());
        let tmp = params.g1.mul(&neg_r2);
        d.add(&tmp);

        let k_open = Big::random(rng);
        let k_sc = Big::new_int(k as isize);

        let mut k_commit = params.h0.mul(&k_sc);
        let tmp1 = params.h1.mul(&k_open);
        k_commit.add(&tmp1);

        let mut origin_exp = k_sc.clone();
        origin_exp.add(&token.key);
        origin_exp.invmodp(&order());

        let ticket = origins.mul(&origin_exp);

        return Ok((
            Self {
                aprime,
                abar,
                d,
                // attributes:
                ticket,
                k_commit,
                commit,
            },
            BBSShowingSecret {
                k_open,
                k_sc,
                r1,
                r2,
            },
        ));
    }

    pub fn verify(&self, pk: &PublicKey) -> Result<(), ()> {
        if self.aprime.equals(&ECP2::new()) {
            return Err(());
        }

        let mut left = pair::ate(&self.aprime, &pk.0);
        left = pair::fexp(&left);

        let mut right = pair::ate(&self.abar, &ECP::generator());
        right = pair::fexp(&right);

        if left.equals(&right) {
            return Ok(());
        } else {
            return Err(());
        }
    }
}

pub struct BoundShowing {
    pub bound: crate::bound::proof::Proof,
}

impl BoundShowing {
    pub fn new(bound: crate::bound::proof::Proof) -> Self {
        Self { bound }
    }

    pub fn show(
        bbs_showing: &BBSShowing,
        secret: &BBSShowingSecret,
        bit_limit: u8,
        params: &Parameters,
        rng: &mut RAND,
    ) -> Result<Self, ()> {
        let proof = bound::proof::Proof::prove(
            &bbs_showing.k_commit,
            &bound::Parameters {
                g: params.h0.clone(),
                h: params.h1.clone(),
            },
            &bound::Opening {
                k: secret.k_sc.clone(),
                r: secret.k_open.clone(),
            },
            bit_limit as usize,
            rng,
        );

        match proof {
            Ok(proof) => Ok(Self::new(proof)),
            Err(_) => Err(()),
        }
    }

    pub fn verify(
        &self,
        bbs_showing: &BBSShowing,
        bit_limit: u8,
        params: &Parameters,
    ) -> Result<(), ()> {
        match self.bound.verify(
            &bbs_showing.k_commit,
            &bound::Parameters {
                g: params.h0.clone(),
                h: params.h1.clone(),
            },
            bit_limit as usize,
        ) {
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }
}

pub struct LinearShowing {
    pub linear: linear::proof::Proof,
}

impl LinearShowing {
    pub fn new(linear: linear::proof::Proof) -> Result<Self, ()> {
        Ok(Self { linear: linear })
    }

    pub fn show(
        bbs: &BBSShowing,
        secret: &BBSShowingSecret,
        token: &Token,
        origin: &ECP2,
        params: &Parameters,
        rng: &mut RAND,
    ) -> Result<Self, ()> {
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
        witness.satisfied(&stmt).expect("witness not satisfied");

        return Self::new(linear);
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
    ) -> Result<(), ()> {
        let stmt = Self::stmt(bbs_showing, origin, params);

        match self.linear.verify(&stmt) {
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }
}
