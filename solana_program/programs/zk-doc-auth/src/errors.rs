//! Custom error codes for ZK-DocAuth.

use anchor_lang::prelude::*;

#[error_code]
pub enum ZKDocAuthError {
    /// 6000 - Groth16 pairing check returned false.
    #[msg("Proof verification failed: pairing check returned false")]
    InvalidProof,

    /// 6001 - The Merkle root in the proof does not match the on-chain root.
    #[msg("Merkle root in proof does not match on-chain root")]
    InvalidMerkleRoot,

    /// 6002 - The issuer account is deactivated.
    #[msg("Issuer account is not active")]
    IssuerInactive,

    /// 6003 - The caller is not the authorized issuer.
    #[msg("Caller is not the authorized issuer")]
    Unauthorized,

    /// 6004 - Proof data is malformed or has incorrect length.
    #[msg("Invalid proof data format")]
    MalformedProof,

    /// 6005 - Number of public inputs does not match the verification key.
    #[msg("Public input count does not match verification key")]
    InputCountMismatch,

    /// 6006 - A G1 point is not on the BN254 curve.
    #[msg("G1 point is not on the curve")]
    InvalidG1Point,

    /// 6007 - A G2 point is not on the BN254 curve.
    #[msg("G2 point is not on the curve")]
    InvalidG2Point,

    /// 6008 - This proof's nullifier has already been recorded.
    #[msg("Proof nullifier has already been used")]
    NullifierAlreadyUsed,

    /// 6009 - The proof has expired based on the timestamp check.
    #[msg("Proof has expired")]
    ProofExpired,

    /// 6010 - alt_bn128 syscall failed.
    #[msg("Elliptic curve operation failed")]
    CurveOperationFailed,
}
