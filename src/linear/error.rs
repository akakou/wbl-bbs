use thiserror::Error;

#[derive(Debug, Error)]
pub enum LinearProofError {
    #[error("failed to verify: {0} != {1} in index {2}")]
    VerifyFailed(String, String, usize),

    #[error("Statement is not well formed (F is not square matrix): {0} != {1} in index {2}")]
    StatementFNotWellFormed(usize, usize, usize),

    #[error("Statement is not well formed (X.len() != F.len()): {0} != {1}")]
    StatementNotWellFormed(usize, usize),

    #[error("Witness is not well formed (Witness.len() != Statement.F.len()): {0} != {1}")]
    WitnessNotWellFormed(usize, usize),

    #[error("Proving failed")]
    ProvingFailed,
}
