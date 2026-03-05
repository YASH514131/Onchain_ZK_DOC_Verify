#![allow(unexpected_cfgs)]

//! # ZK-DocAuth Solana Program
//!
//! Zero Knowledge Document Authentication Protocol on Solana.
//!
//! This Anchor program provides:
//! - Issuer registration and Merkle root management.
//! - Revocation root updates.
//! - Groth16 proof verification via `alt_bn128` precompile syscalls.
//!
//! ## Account Layout
//!
//! - `IssuerAccount` (PDA: ["issuer", issuer_pubkey]): Stores merkle root,
//!   revocation root, tree size, and issuer metadata.
//! - `VerificationKeyAccount` (PDA: ["vk", issuer_pubkey]): Stores the
//!   Groth16 verification key (alpha, beta, gamma, delta, IC points).
//! - `NullifierAccount` (PDA: ["nullifier", nullifier_hash]): Prevents
//!   proof replay by recording used nullifiers.

use anchor_lang::prelude::*;

pub mod errors;
pub mod events;
pub mod state;
pub mod verifier;

use errors::ZKDocAuthError;
use events::*;
use state::*;
use verifier::groth16;

declare_id!("BXyrGdBKq9i9mpzP6AwAYy5pfSMCiEb1sZzqDySy41Qa");

#[program]
pub mod zk_doc_auth {
    use super::*;

    // ── Initialize Issuer ────────────────────────────────────────────

    /// Register a new trusted KYC issuer.
    ///
    /// Creates an `IssuerAccount` PDA owned by the calling authority.
    /// The account stores the issuer's Merkle root (initially zero)
    /// and metadata.
    pub fn initialize_issuer(
        ctx: Context<InitializeIssuer>,
        issuer_name: String,
    ) -> Result<()> {
        let issuer = &mut ctx.accounts.issuer_account;
        issuer.authority = ctx.accounts.authority.key();
        issuer.merkle_root = [0u8; 32];
        issuer.revocation_root = [0u8; 32];
        issuer.tree_size = 0;
        issuer.last_updated = Clock::get()?.unix_timestamp;
        issuer.name = issuer_name.clone();
        issuer.is_active = true;

        emit!(IssuerInitialized {
            authority: issuer.authority,
            name: issuer_name,
            timestamp: issuer.last_updated,
        });

        Ok(())
    }

    // ── Update Merkle Root ───────────────────────────────────────────

    /// Update the Merkle root for a registered issuer.
    ///
    /// Called after inserting or revoking credentials in the off-chain
    /// Merkle tree. Only the issuer authority can call this.
    pub fn update_merkle_root(
        ctx: Context<UpdateMerkleRoot>,
        new_root: [u8; 32],
        tree_size: u64,
    ) -> Result<()> {
        let issuer = &mut ctx.accounts.issuer_account;

        require!(issuer.is_active, ZKDocAuthError::IssuerInactive);

        issuer.merkle_root = new_root;
        issuer.tree_size = tree_size;
        issuer.last_updated = Clock::get()?.unix_timestamp;

        emit!(MerkleRootUpdated {
            issuer: issuer.authority,
            new_root,
            tree_size,
            timestamp: issuer.last_updated,
        });

        Ok(())
    }

    // ── Update Revocation Root ───────────────────────────────────────

    /// Update the revocation epoch root.
    pub fn update_revocation_root(
        ctx: Context<UpdateRevocationRoot>,
        new_root: [u8; 32],
    ) -> Result<()> {
        let issuer = &mut ctx.accounts.issuer_account;

        issuer.revocation_root = new_root;
        issuer.last_updated = Clock::get()?.unix_timestamp;

        emit!(RevocationRootUpdated {
            issuer: issuer.authority,
            new_root,
            timestamp: issuer.last_updated,
        });

        Ok(())
    }

    // ── Verify Proof ─────────────────────────────────────────────────

    /// Verify a Groth16 zero-knowledge proof on-chain.
    ///
    /// Accepts a serialized proof (A, B, C) and public inputs, then:
    /// 1. Validates the Merkle root matches the on-chain issuer root.
    /// 2. Executes the Groth16 pairing verification equation.
    /// 3. Records the nullifier to prevent replay.
    /// 4. Emits a `ProofVerified` event on success.
    pub fn verify_proof(
        ctx: Context<VerifyProof>,
        proof_a: [u8; 64],
        proof_b: [u8; 128],
        proof_c: [u8; 64],
        public_inputs: Vec<[u8; 32]>,
        nullifier_hash: [u8; 32],
    ) -> Result<()> {
        let issuer = &ctx.accounts.issuer_account;

        // 1. Check issuer is active.
        require!(issuer.is_active, ZKDocAuthError::IssuerInactive);

        // 2. Validate public input count matches VK.
        require!(
            public_inputs.len() == 4,
            ZKDocAuthError::InputCountMismatch
        );

        // 3. Validate Merkle root matches on-chain root.
        require!(
            public_inputs[0] == issuer.merkle_root,
            ZKDocAuthError::InvalidMerkleRoot
        );

        // 4. Execute Groth16 verification.
        //
        // In production, this calls the alt_bn128 pairing precompile:
        //   e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1
        //
        // The verification key points (alpha, beta, gamma, delta, IC)
        // are loaded from the VerificationKeyAccount.
        let vk = &ctx.accounts.vk_account;
        let is_valid = groth16::verify(
            &proof_a,
            &proof_b,
            &proof_c,
            &public_inputs,
            vk,
        )?;

        require!(is_valid, ZKDocAuthError::InvalidProof);

        // 5. Record nullifier to prevent replay.
        let nullifier = &mut ctx.accounts.nullifier_account;
        nullifier.proof_hash = nullifier_hash;
        nullifier.verified_at = Clock::get()?.unix_timestamp;
        nullifier.verifier = ctx.accounts.submitter.key();

        // 6. Emit verification event.
        emit!(ProofVerified {
            submitter: ctx.accounts.submitter.key(),
            issuer: issuer.authority,
            timestamp: nullifier.verified_at,
            merkle_root: issuer.merkle_root,
        });

        Ok(())
    }

    // ── Store Verification Key ───────────────────────────────────────

    /// Store or update the Groth16 verification key for an issuer.
    pub fn store_verification_key(
        ctx: Context<StoreVerificationKey>,
        alpha_g1: [u8; 64],
        beta_g2: [u8; 128],
        gamma_g2: [u8; 128],
        delta_g2: [u8; 128],
        ic: Vec<[u8; 64]>,
    ) -> Result<()> {
        let vk = &mut ctx.accounts.vk_account;

        vk.alpha_g1 = alpha_g1;
        vk.beta_g2 = beta_g2;
        vk.gamma_g2 = gamma_g2;
        vk.delta_g2 = delta_g2;
        vk.ic = ic;

        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Instruction Contexts
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Accounts)]
pub struct InitializeIssuer<'info> {
    #[account(
        init,
        payer = authority,
        space = IssuerAccount::SIZE,
        seeds = [b"issuer", authority.key().as_ref()],
        bump,
    )]
    pub issuer_account: Account<'info, IssuerAccount>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateMerkleRoot<'info> {
    #[account(
        mut,
        seeds = [b"issuer", authority.key().as_ref()],
        bump,
        has_one = authority @ ZKDocAuthError::Unauthorized,
    )]
    pub issuer_account: Account<'info, IssuerAccount>,

    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct UpdateRevocationRoot<'info> {
    #[account(
        mut,
        seeds = [b"issuer", authority.key().as_ref()],
        bump,
        has_one = authority @ ZKDocAuthError::Unauthorized,
    )]
    pub issuer_account: Account<'info, IssuerAccount>,

    pub authority: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(proof_a: [u8; 64], proof_b: [u8; 128], proof_c: [u8; 64], public_inputs: Vec<[u8; 32]>, nullifier_hash: [u8; 32])]
pub struct VerifyProof<'info> {
    #[account(
        seeds = [b"issuer", issuer_account.authority.as_ref()],
        bump,
    )]
    pub issuer_account: Account<'info, IssuerAccount>,

    #[account(
        seeds = [b"vk", issuer_account.authority.as_ref()],
        bump,
    )]
    pub vk_account: Account<'info, VerificationKeyAccount>,

    #[account(
        init,
        payer = submitter,
        space = NullifierAccount::SIZE,
        seeds = [b"nullifier", nullifier_hash.as_ref()],
        bump,
    )]
    pub nullifier_account: Account<'info, NullifierAccount>,

    #[account(mut)]
    pub submitter: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct StoreVerificationKey<'info> {
    #[account(
        seeds = [b"issuer", authority.key().as_ref()],
        bump,
        has_one = authority @ ZKDocAuthError::Unauthorized,
    )]
    pub issuer_account: Account<'info, IssuerAccount>,

    #[account(
        init_if_needed,
        payer = authority,
        space = VerificationKeyAccount::MAX_SIZE,
        seeds = [b"vk", authority.key().as_ref()],
        bump,
    )]
    pub vk_account: Account<'info, VerificationKeyAccount>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}
