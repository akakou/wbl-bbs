use thiserror::Error;

use crate::{bound::MAX_BIT_LENGTH, linear::error::LinearProofError};

#[derive(Debug, Error)]
pub enum BoundProofError {
    #[error("invalid bit length: now we only support bit_length < {MAX_BIT_LENGTH} but bit_length = {0}")]
    InvalidBitLength(usize),

    #[error("failed to prove: {0}")]
    ProveFailed(LinearProofError),

    #[error("failed to verify: {0}")]
    VerifyFailed(LinearProofError),

    #[error("witness and statement are not satisfied: {0}")]
    WitnessNotSatisfied(LinearProofError),
}
