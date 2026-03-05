//! Event definitions emitted by the ZK-DocAuth program.

use anchor_lang::prelude::*;

/// Emitted when a new issuer is registered.
#[event]
pub struct IssuerInitialized {
    pub authority: Pubkey,
    pub name: String,
    pub timestamp: i64,
}

/// Emitted when the Merkle root is updated.
#[event]
pub struct MerkleRootUpdated {
    pub issuer: Pubkey,
    pub new_root: [u8; 32],
    pub tree_size: u64,
    pub timestamp: i64,
}

/// Emitted when the revocation root is updated.
#[event]
pub struct RevocationRootUpdated {
    pub issuer: Pubkey,
    pub new_root: [u8; 32],
    pub timestamp: i64,
}

/// Emitted when a ZK proof is successfully verified on-chain.
#[event]
pub struct ProofVerified {
    pub submitter: Pubkey,
    pub issuer: Pubkey,
    pub timestamp: i64,
    pub merkle_root: [u8; 32],
}
