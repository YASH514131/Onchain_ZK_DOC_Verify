#![allow(unexpected_cfgs)]

//! Groth16 verification module.
//!
//! Implements the Groth16 verification equation using Solana's `alt_bn128`
//! syscalls for elliptic curve operations over the BN254 curve.
//!
//! ## Verification Equation
//!
//! ```text
//! e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1_GT
//! ```
//!
//! where `vk_x = IC[0] + sum(public_inputs[i] * IC[i+1])`.
//!
//! ## Syscalls Used
//!
//! - `sol_alt_bn128_group_op(ADD, ...)`:  G1 point addition
//! - `sol_alt_bn128_group_op(MUL, ...)`:  G1 scalar multiplication
//! - `sol_alt_bn128_group_op(PAIRING, ...)`: Multi-pairing check

pub mod groth16 {
    use anchor_lang::prelude::*;
    use crate::errors::ZKDocAuthError;
    use crate::state::VerificationKeyAccount;

    /// BN254 field modulus for validation.
    const BN254_FIELD_MODULUS: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
        0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
        0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d,
        0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
    ];

    /// alt_bn128 group operation codes.
    const ALT_BN128_ADD: u64 = 0;
    const ALT_BN128_MUL: u64 = 1;
    const ALT_BN128_PAIRING: u64 = 2;

    /// Verify a Groth16 proof against the stored verification key.
    ///
    /// # Arguments
    ///
    /// * `proof_a` - G1 point A (64 bytes, uncompressed).
    /// * `proof_b` - G2 point B (128 bytes, uncompressed).
    /// * `proof_c` - G1 point C (64 bytes, uncompressed).
    /// * `public_inputs` - Array of 32-byte field elements.
    /// * `vk` - The verification key account.
    ///
    /// # Returns
    ///
    /// `true` if the pairing check passes, `false` otherwise.
    pub fn verify(
        proof_a: &[u8; 64],
        proof_b: &[u8; 128],
        proof_c: &[u8; 64],
        public_inputs: &[[u8; 32]],
        vk: &VerificationKeyAccount,
    ) -> Result<bool> {
        // ── Step 1: Compute vk_x = IC[0] + sum(public_inputs[i] * IC[i+1]) ──

        require!(
            public_inputs.len() + 1 == vk.ic.len(),
            ZKDocAuthError::InputCountMismatch
        );

        // Start with IC[0].
        let mut vk_x = vk.ic[0];

        // Accumulate: vk_x += public_inputs[i] * IC[i+1]
        for (i, input) in public_inputs.iter().enumerate() {
            // Scalar multiplication: input * IC[i+1]
            let term = bn128_scalar_mul(&vk.ic[i + 1], input)?;
            // G1 addition: vk_x += term
            vk_x = bn128_add(&vk_x, &term)?;
        }

        // ── Step 2: Negate A ──
        // -A has the same x-coordinate but negated y-coordinate.
        let neg_a = negate_g1(proof_a);

        // ── Step 3: Construct pairing input ──
        //
        // We check: e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1
        //
        // The pairing syscall takes pairs of (G1, G2) points and returns 1
        // if the product of pairings equals 1 in GT.
        let mut pairing_input = Vec::with_capacity(4 * (64 + 128));

        // Pair 1: (-A, B)
        pairing_input.extend_from_slice(&neg_a);
        pairing_input.extend_from_slice(proof_b);

        // Pair 2: (alpha, beta)
        pairing_input.extend_from_slice(&vk.alpha_g1);
        pairing_input.extend_from_slice(&vk.beta_g2);

        // Pair 3: (vk_x, gamma)
        pairing_input.extend_from_slice(&vk_x);
        pairing_input.extend_from_slice(&vk.gamma_g2);

        // Pair 4: (C, delta)
        pairing_input.extend_from_slice(proof_c);
        pairing_input.extend_from_slice(&vk.delta_g2);

        // ── Step 4: Execute pairing check ──
        let result = bn128_pairing(&pairing_input)?;

        Ok(result)
    }

    // ── BN128 Operations ─────────────────────────────────────────────

    /// G1 point addition: P + Q.
    fn bn128_add(p: &[u8; 64], q: &[u8; 64]) -> Result<[u8; 64]> {
        let mut input = [0u8; 128];
        input[..64].copy_from_slice(p);
        input[64..].copy_from_slice(q);

        let mut output = [0u8; 64];

        #[cfg(target_os = "solana")]
        {
            let result = unsafe {
                sol_alt_bn128_group_op(
                    ALT_BN128_ADD,
                    input.as_ptr(),
                    input.len() as u64,
                    output.as_mut_ptr(),
                )
            };
            if result != 0 {
                return Err(ZKDocAuthError::CurveOperationFailed.into());
            }
        }

        #[cfg(not(target_os = "solana"))]
        {
            // Off-chain: passthrough for testing.
            output.copy_from_slice(&input[..64]);
        }

        Ok(output)
    }

    /// G1 scalar multiplication: scalar * P.
    fn bn128_scalar_mul(p: &[u8; 64], scalar: &[u8; 32]) -> Result<[u8; 64]> {
        let mut input = [0u8; 96];
        input[..64].copy_from_slice(p);
        input[64..].copy_from_slice(scalar);

        let mut output = [0u8; 64];

        #[cfg(target_os = "solana")]
        {
            let result = unsafe {
                sol_alt_bn128_group_op(
                    ALT_BN128_MUL,
                    input.as_ptr(),
                    input.len() as u64,
                    output.as_mut_ptr(),
                )
            };
            if result != 0 {
                return Err(ZKDocAuthError::CurveOperationFailed.into());
            }
        }

        #[cfg(not(target_os = "solana"))]
        {
            output.copy_from_slice(&input[..64]);
        }

        Ok(output)
    }

    /// Multi-pairing check.
    ///
    /// Returns `true` if the product of pairings equals 1 in GT.
    fn bn128_pairing(input: &[u8]) -> Result<bool> {
        #[cfg(target_os = "solana")]
        {
            let mut output = [0u8; 32];
            let result = unsafe {
                sol_alt_bn128_group_op(
                    ALT_BN128_PAIRING,
                    input.as_ptr(),
                    input.len() as u64,
                    output.as_mut_ptr(),
                )
            };
            if result != 0 {
                return Err(ZKDocAuthError::CurveOperationFailed.into());
            }
            // Pairing check returns 1 (as a 32-byte big-endian integer) if valid.
            Ok(output[31] == 1 && output[..31].iter().all(|&b| b == 0))
        }

        #[cfg(not(target_os = "solana"))]
        {
            // Off-chain simulation: always returns true for testing.
            let _ = input;
            Ok(true)
        }
    }

    /// Negate a G1 point: -(x, y) = (x, p - y).
    ///
    /// Point encoding is big-endian: x in bytes [0..32], y in bytes [32..64].
    /// The BN254 field prime p is also stored big-endian.
    fn negate_g1(point: &[u8; 64]) -> [u8; 64] {
        let mut result = *point;

        // Check if the point is the point at infinity (all zeros).
        if point[32..64].iter().all(|&b| b == 0) {
            return result;
        }

        // Negate y: y_neg = FIELD_MODULUS - y (big-endian subtraction).
        let mut borrow: u16 = 0;
        for i in (32..64).rev() {
            let p_byte = BN254_FIELD_MODULUS[i - 32] as u16;
            let y_byte = result[i] as u16;
            let diff = p_byte.wrapping_sub(y_byte).wrapping_sub(borrow);
            result[i] = diff as u8;
            borrow = if p_byte < y_byte + borrow { 1 } else { 0 };
        }

        result
    }

    // ── Solana Syscall Declaration ───────────────────────────────────

    #[cfg(target_os = "solana")]
    extern "C" {
        fn sol_alt_bn128_group_op(
            group_op: u64,
            input: *const u8,
            input_len: u64,
            output: *mut u8,
        ) -> u64;
    }
}
