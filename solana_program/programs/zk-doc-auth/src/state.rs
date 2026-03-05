//! Account state definitions for ZK-DocAuth.

use anchor_lang::prelude::*;

// ─────────────────────────────────────────────────────────────────────────────
// Issuer Account
// ─────────────────────────────────────────────────────────────────────────────

/// Stores the state of a registered KYC issuer.
///
/// PDA seeds: ["issuer", authority_pubkey]
///
/// Layout:
///   discriminator:     8 bytes
///   authority:        32 bytes  (Pubkey)
///   merkle_root:      32 bytes  ([u8; 32])
///   revocation_root:  32 bytes  ([u8; 32])
///   tree_size:         8 bytes  (u64)
///   last_updated:      8 bytes  (i64)
///   name:           4+60 bytes  (String, max 60 chars)
///   is_active:         1 byte   (bool)
///   ─────────────────────────
///   Total:           185 bytes
#[account]
pub struct IssuerAccount {
    /// The Solana public key authorized to manage this issuer account.
    pub authority: Pubkey,

    /// The current Merkle root of the valid credentials tree.
    /// Updated each time a credential is inserted or revoked.
    pub merkle_root: [u8; 32],

    /// The current revocation epoch root (for freshness checks).
    pub revocation_root: [u8; 32],

    /// Number of leaves (credentials) in the Merkle tree.
    pub tree_size: u64,

    /// Unix timestamp of the last root update.
    pub last_updated: i64,

    /// Human-readable issuer name (max 60 bytes).
    pub name: String,

    /// Whether this issuer is currently active. Inactive issuers cannot
    /// have their proofs verified.
    pub is_active: bool,
}

impl IssuerAccount {
    /// Total account size including Anchor discriminator.
    pub const SIZE: usize = 8  // discriminator
        + 32  // authority
        + 32  // merkle_root
        + 32  // revocation_root
        + 8   // tree_size
        + 8   // last_updated
        + 4 + 60  // name (borsh string: 4-byte len + data)
        + 1;  // is_active
}

// ─────────────────────────────────────────────────────────────────────────────
// Verification Key Account
// ─────────────────────────────────────────────────────────────────────────────

/// Stores the Groth16 verification key for an issuer's circuit.
///
/// PDA seeds: ["vk", issuer_pubkey]
///
/// The VK consists of curve points used in the pairing check:
///   e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1
///
/// where vk_x = IC[0] + sum(public_inputs[i] * IC[i+1])
#[account]
pub struct VerificationKeyAccount {
    /// Alpha point in G1 (uncompressed, 64 bytes).
    pub alpha_g1: [u8; 64],

    /// Beta point in G2 (uncompressed, 128 bytes).
    pub beta_g2: [u8; 128],

    /// Gamma point in G2 (uncompressed, 128 bytes).
    pub gamma_g2: [u8; 128],

    /// Delta point in G2 (uncompressed, 128 bytes).
    pub delta_g2: [u8; 128],

    /// IC points in G1 (one per public input + 1).
    /// For 4 public inputs: 5 G1 points = 5 * 64 = 320 bytes.
    pub ic: Vec<[u8; 64]>,
}

impl VerificationKeyAccount {
    /// Maximum account size (5 IC points for 4 public inputs).
    pub const MAX_SIZE: usize = 8    // discriminator
        + 64    // alpha_g1
        + 128   // beta_g2
        + 128   // gamma_g2
        + 128   // delta_g2
        + 4 + (5 * 64);  // ic vec (borsh: 4-byte len + 5 * 64)
}

// ─────────────────────────────────────────────────────────────────────────────
// Nullifier Account
// ─────────────────────────────────────────────────────────────────────────────

/// Records a used proof nullifier to prevent replay attacks.
///
/// PDA seeds: ["nullifier", nullifier_hash]
///
/// Once created, the existence of this account proves that a specific
/// proof has already been submitted. Any subsequent attempt to submit
/// the same proof will fail (PDA already initialized).
#[account]
pub struct NullifierAccount {
    /// Hash of the proof (first 32 bytes of proof.A).
    pub proof_hash: [u8; 32],

    /// Unix timestamp when the proof was verified.
    pub verified_at: i64,

    /// Public key of the account that submitted the proof.
    pub verifier: Pubkey,
}

impl NullifierAccount {
    pub const SIZE: usize = 8   // discriminator
        + 32  // proof_hash
        + 8   // verified_at
        + 32; // verifier
}
