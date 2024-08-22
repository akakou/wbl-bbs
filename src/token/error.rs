use thiserror::Error;

#[derive(Debug, Error)]
pub enum TokenProofError {
    #[error("Commit check failed: {0} != {1}")]
    CommitCheckFailed(String, String),

    #[error("Pairing check failed(linear): {0} != {1}")]
    PairingCheckFailedInLinear(String, String),

    #[error("Pairing check failed(token): {0} != {1}")]
    PairingCheckFailedInToken(String, String),

    #[error("Pairing check failed(show): {0} != {1}")]
    PairingCheckFailedInShowing(String, String),

    #[error("Fialed to verfy Bound proof: {0}")]
    BoundProofError(crate::bound::error::BoundProofError),

    #[error("Failed to verify linear proof: {0}")]
    LinearProofError(crate::linear::error::LinearProofError),

    #[error("APrime is unity")]
    APrimeIsUnity,

    #[error("failed to verify: {0} != {1} in index {2}")]
    VerifyFailed(String, String, usize),

    #[error("Proving failed")]
    ProvingFailed,
}
