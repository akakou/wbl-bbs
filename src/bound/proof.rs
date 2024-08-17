use std::vec;

use snowbridge_amcl::{
    bls381::{big::Big, ecp2::ECP2, rom},
    rand::RAND,
};

use crate::linear::{self, utils::order};

use super::{error::BoundProofError, Opening, Parameters, MAX_BIT_LENGTH};

pub struct Proof {
    pub ci: Vec<ECP2>,
    pub proof: linear::proof::Proof,
}

impl Proof {
    pub fn prove(
        commit: &ECP2,
        params: &Parameters,
        open: &Opening,
        bit_length: usize,
        rng: &mut RAND,
    ) -> Result<Self, BoundProofError> {
        if bit_length > MAX_BIT_LENGTH {
            return Err(BoundProofError::InvalidBitLength(bit_length));
        }

        let mut k = vec![0u8; rom::MODBYTES];
        open.k.to_bytes(&mut k);

        let mut bit_rs = vec![Big::new(); bit_length];
        let mut bit_coms = vec![ECP2::new(); bit_length];
        let mut digits = vec![Big::new(); bit_length];

        let mut val = k[k.len() - 1];

        for i in 0..bit_length {
            let bit_r = Big::random(rng);
            let mut digit = Big::new_int(0);
            let mut bitcom = params.h.mul(&bit_r);

            if val % 2 == 1 {
                digit = Big::new_int(1);
                bitcom.add(&params.g);
            }

            bit_rs[i] = bit_r;
            digits[i] = digit;
            bit_coms[i] = bitcom;

            val = val / 2;
        }

        let input_base = 3 * bit_length;
        let input_len = input_base + 1;

        let output_base = 2 * bit_length;
        let output_len = output_base + 1;

        let mut stmt = linear::statement::Statement::new(
            vec![vec![ECP2::new(); input_len]; output_len],
            vec![ECP2::new(); output_len],
        );

        let mut witness = linear::witeness::Witness(vec![Big::new(); input_len]);

        // Open digits
        for i in 0..bit_length {
            stmt.x[i] = bit_coms[i].clone();
            stmt.f[i][i] = params.g.clone();
            stmt.f[i][bit_length + i] = params.h.clone();
            witness.0[i] = digits[i].clone();
            witness.0[bit_length + i] = bit_rs[i].clone();
        }

        let mut neg_g = params.g.clone();
        neg_g.neg();

        for i in 0..bit_length {
            let output_index = output_base + i;
            witness.0[output_index] = Big::modmul(&digits[i], &bit_rs[i], &order())
        }

        Self::compute_part_of_statement(&mut stmt, &bit_coms, commit, params, bit_length);

        witness.0[input_base] = open.r.clone();

        match witness.satisfied(&stmt) {
            Ok(_) => {}
            Err(e) => return Err(BoundProofError::WitnessNotSatisfied(e)),
        }

        match linear::proof::Proof::prove(&stmt, &witness, rng) {
            Ok(proof) => Ok(Self {
                ci: bit_coms,
                proof: proof,
            }),
            Err(e) => Err(BoundProofError::ProveFailed(e)),
        }
    }

    pub fn verify(
        &self,
        comm: &ECP2,
        params: &Parameters,
        bit_length: usize,
    ) -> Result<(), BoundProofError> {
        let input_base = 3 * bit_length;
        let input_len = input_base + 1;

        let output_base = 2 * bit_length;
        let output_len = output_base + 1;

        let mut stmt = linear::statement::Statement::new(
            vec![vec![ECP2::new(); input_len]; output_len],
            vec![ECP2::new(); output_len],
        );

        Self::compute_part_of_statement(&mut stmt, &self.ci, comm, params, bit_length);

        match self.proof.verify(&stmt) {
            Ok(_) => Ok(()),
            Err(e) => Err(BoundProofError::VerifyFailed(e)),
        }
    }


    fn compute_part_of_statement(stmt : &mut linear::statement::Statement, bit_coms: &[ECP2], comm: &ECP2, params: &Parameters, bit_length: usize) {
        let input_base = 3 * bit_length;
        let output_base = 2 * bit_length;

        for i in 0..bit_length {
            stmt.x[i] = bit_coms[i].clone();
            stmt.f[i][i] = params.g.clone();
            stmt.f[i][bit_length + i] = params.h.clone();
        }

        let mut neg_g = params.g.clone();
        neg_g.neg();

        for i in 0..bit_length {
            let y = bit_length + i;
            stmt.f[y][i] = bit_coms[i].clone();
            stmt.f[y][i].add(&neg_g);

            let output_index = output_base + i;
            stmt.f[y][output_index] = params.h.clone();
            stmt.f[y][output_index].neg();
        }

        stmt.f[output_base][0] = params.g.clone();

        let two = Big::new_int(2);
        for i in 1..bit_length {
            stmt.f[output_base][i] = stmt.f[output_base][i - 1].mul(&two);
        }

        stmt.f[output_base][input_base] = params.h.clone();
        stmt.x[output_base] = comm.clone();
    }
}
