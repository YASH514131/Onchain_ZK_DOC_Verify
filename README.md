# ZK-DocAuth-Solana

## Zero Knowledge Document Authentication Protocol on Solana

**Version:** 0.1.0-alpha  
**License:** MIT / Apache-2.0  
**Status:** Research & Development  
**Last Updated:** 2026-02-26

---

## Table of Contents

1. [Problem Statement](#1-problem-statement)
2. [High-Level Architecture](#2-high-level-architecture)
3. [Solana-Specific Design](#3-solana-specific-design)
4. [Cryptographic Primitives](#4-cryptographic-primitives)
5. [Commitment Scheme](#5-commitment-scheme)
6. [Merkle Tree Design](#6-merkle-tree-design)
7. [Revocation Mechanism](#7-revocation-mechanism)
8. [Circuit Definition](#8-circuit-definition)
9. [R1CS Representation](#9-r1cs-representation)
10. [Range Proof Logic](#10-range-proof-logic)
11. [Folder Structure](#11-folder-structure)
12. [Tooling Stack](#12-tooling-stack)
13. [Step-by-Step Proof Flow](#13-step-by-step-proof-flow)
14. [Security Analysis](#14-security-analysis)
15. [Performance Analysis](#15-performance-analysis)
16. [Real World Use Cases](#16-real-world-use-cases)
17. [Future Work](#17-future-work)

---

## 1. Problem Statement

### 1.1 The Broken State of Identity Verification

Traditional Know Your Customer (KYC) flows are architecturally incompatible with user privacy. Every compliance-driven identity check today requires the user to transmit raw personally identifiable information (PII) -- full legal name, date of birth, passport number, residential address, biometric data -- to a verifying party that stores it in a centralized database.

This model has several critical failures:

**Data Leakage at Rest.** Centralized KYC databases are high-value targets. The 2017 Equifax breach exposed 147 million records. The 2019 First American Financial breach leaked 885 million documents. KYC aggregators hold the same class of data with the same vulnerability surface.

**Redundant Submission.** A single user performing KYC across five exchanges, two banks, and a brokerage submits the same identity documents eight times to eight independent custodians, each representing an independent attack surface.

**Regulatory Friction.** GDPR Article 5(1)(c) mandates data minimization -- collect only what is strictly necessary. Transmitting a full passport scan to prove `age >= 18` is a direct violation of this principle. CCPA, LGPD, PIPL, and India's DPDP Act impose similar constraints.

**Identity Theft Amplification.** Once PII is exfiltrated, it cannot be "unbreached." Unlike passwords, a user cannot rotate their date of birth or national identity number.

**No Selective Disclosure.** Current flows are all-or-nothing. There is no mechanism to prove a single property (e.g., nationality) without revealing every other field on the document.

### 1.2 Why Zero Knowledge Proofs Solve This

A zero-knowledge proof (ZKP) allows a prover to convince a verifier that a statement is true without revealing any information beyond the truth of the statement itself. Formally, a ZKP system satisfies three properties:

- **Completeness:** If the statement is true and both parties follow the protocol, the verifier accepts.
- **Soundness:** If the statement is false, no computationally bounded prover can convince the verifier to accept, except with negligible probability.
- **Zero-Knowledge:** The verifier learns nothing beyond the validity of the statement. There exists a simulator that can produce transcripts indistinguishable from real interactions.

Applied to document authentication:

| Traditional KYC | ZK-DocAuth |
|---|---|
| Sends full passport scan | Sends 256-byte proof |
| Verifier sees all fields | Verifier sees only claim validity |
| Data stored in centralized DB | No PII leaves user device |
| Each verifier gets raw PII | Each verifier gets a proof |
| Breach exposes all users | Nothing to breach |

ZK-DocAuth-Solana constructs a protocol where a user can prove:

- `nationality == "India"` (without revealing name, DOB, or passport number)
- `age >= 18` (without revealing exact date of birth)
- `document issued by trusted authority X` (without revealing document content)
- `credential is not revoked` (without revealing which credential)
- `hash(name) == expected_hash` (without revealing the name)
- `nationality in {India, USA, UK, Germany, ...}` (set membership without revealing which)

All proofs are verified on-chain by a Solana program in under 200,000 compute units.

---

## 2. High-Level Architecture

### 2.1 System Components

```
+---------------------+       +---------------------+       +---------------------+
|                     |       |                     |       |                     |
|   ISSUER            |       |   USER WALLET       |       |   VERIFIER          |
|   (Trusted KYC      |       |   (Client-side)     |       |   (On-chain Solana  |
|    Authority)       |       |                     |       |    Program)         |
|                     |       |                     |       |                     |
|  - Verify docs      |  VC   |  - Store credential |  Proof|  - Accept proof     |
|  - Extract fields   |------>|  - Store private key |------>|  - Verify Groth16   |
|  - Compute hash     |       |  - Generate zkProof |       |  - Check Merkle root|
|  - Build Merkle tree|       |  - Submit to chain  |       |  - Check revocation |
|  - Publish root     |       |                     |       |  - Emit result      |
|                     |       |                     |       |                     |
+---------------------+       +---------------------+       +---------------------+
         |                                                           |
         |              +-------------------------+                  |
         +------------->|   SOLANA BLOCKCHAIN     |<-----------------+
                        |                         |
                        |  - Merkle root account  |
                        |  - Revocation registry  |
                        |  - Verification logs    |
                        |  - Program (Anchor)     |
                        +-------------------------+
```

### 2.2 Component A: Issuer (Trusted KYC Authority)

The Issuer is an off-chain entity (government agency, licensed KYC provider, or federated identity provider) that performs document verification through conventional means (optical inspection, NFC chip read, database cross-reference, biometric match).

**Issuer Workflow:**

1. **Document Intake.** Receive raw document (passport, national ID, driver's license) via secure channel.

2. **Field Extraction.** Parse structured fields from the document:

```
struct Credential {
    name:          String,       // "YASH KUMAR"
    dob:           u32,          // 20040315 (YYYYMMDD as integer)
    nationality:   u16,          // ISO 3166-1 numeric: 356 (India)
    document_id:   [u8; 32],     // SHA256 of passport number
    expiry:        u32,          // 20350101 (YYYYMMDD as integer)
    issuer_id:     Pubkey,       // Solana pubkey of issuing authority
    issued_at:     i64,          // Unix timestamp
}
```

3. **Credential Commitment.** Compute a Poseidon hash commitment over the credential fields:

```
credential_hash = Poseidon(
    hash(name),
    dob,
    nationality_code,
    hash(document_id),
    expiry
)
```

4. **Merkle Insertion.** Insert `credential_hash` as a leaf in a binary Merkle tree. The tree is maintained by the Issuer off-chain and the root is published on-chain.

5. **Signature.** The Issuer signs the `(credential_hash, merkle_root, leaf_index)` tuple with their Solana keypair. This signature is delivered to the user alongside the credential.

6. **Root Publication.** The Issuer submits a transaction to the Solana program that updates the stored Merkle root for their issuer account.

### 2.3 Component B: User Wallet (Flutter Mobile App)

The User Wallet is a Flutter-based cross-platform application (mobile + web) that holds the user's credential and generates zero-knowledge proofs locally. The app is built with Provider state management and uses pure-Dart implementations of Poseidon hashing and Merkle trees.

**User Wallet Responsibilities:**

- Store the full `Credential` struct in encrypted local storage (AES-256-GCM, key derived from user passphrase via Argon2id).
- Store the Merkle path (sibling hashes and path indices) received from the Issuer.
- Generate a Groth16 proof for a given claim (e.g., `age >= 18`) using the circuit's WASM prover.
- Submit the proof, public inputs, and a transaction to the Solana program.
- Never transmit raw credential fields to any party.

**Proof Generation (Local):**

```
inputs = {
    // Private (witness)
    name:           field_encode("YASH KUMAR"),
    dob:            20040315,
    nationality:    356,
    document_id:    hash("A12345678"),
    expiry:         20350101,
    merkle_path:    [h0, h1, ..., h_{d-1}],
    merkle_indices: [0, 1, ..., b_{d-1}],

    // Public
    merkle_root:    <32 bytes>,
    current_year:   2026,
    min_age:        18,
    expected_nationality_hash: Poseidon(356),
}

proof = groth16.prove(proving_key, circuit_wasm, inputs)
```

### 2.4 Component C: Verifier (On-chain Solana Program)

The Verifier is an Anchor-based Solana program that accepts a Groth16 proof and public inputs, performs pairing-based verification, and emits an acceptance or rejection event.

**Verifier Responsibilities:**

- Deserialize proof elements `(A, B, C)` from the transaction data.
- Deserialize public inputs `(merkle_root, current_year, min_age, expected_nationality_hash)`.
- Load the verification key (stored in a program account or hardcoded).
- Execute the Groth16 verification equation using the `alt_bn128` syscalls.
- Validate that `merkle_root` matches the on-chain stored root for the claimed issuer.
- Validate that the revocation root check passes.
- Emit a `ProofVerified` event or return an error.

---

## 3. Solana-Specific Design

### 3.1 Anchor Program Structure

```rust
#[program]
pub mod zk_doc_auth {
    use super::*;

    pub fn initialize_issuer(
        ctx: Context<InitializeIssuer>,
        issuer_name: String,
    ) -> Result<()> { ... }

    pub fn update_merkle_root(
        ctx: Context<UpdateMerkleRoot>,
        new_root: [u8; 32],
        tree_size: u64,
    ) -> Result<()> { ... }

    pub fn update_revocation_root(
        ctx: Context<UpdateRevocationRoot>,
        new_root: [u8; 32],
    ) -> Result<()> { ... }

    pub fn verify_proof(
        ctx: Context<VerifyProof>,
        proof: ProofData,
        public_inputs: PublicInputs,
    ) -> Result<()> { ... }
}
```

### 3.2 Account Model

**IssuerAccount (PDA)**

```
Seeds: ["issuer", issuer_pubkey]
Size:  8 (discriminator) + 32 (authority) + 32 (merkle_root)
       + 32 (revocation_root) + 8 (tree_size) + 8 (last_updated)
       + 64 (name) + 1 (is_active)
Total: 185 bytes
Rent:  ~0.00144 SOL
```

```rust
#[account]
pub struct IssuerAccount {
    pub authority:        Pubkey,      // 32 bytes
    pub merkle_root:      [u8; 32],    // 32 bytes
    pub revocation_root:  [u8; 32],    // 32 bytes
    pub tree_size:        u64,         // 8 bytes
    pub last_updated:     i64,         // 8 bytes
    pub name:             String,      // 4 + up to 60 bytes
    pub is_active:        bool,        // 1 byte
}
```

**VerificationKeyAccount (PDA)**

```
Seeds: ["vk", issuer_pubkey]
Size:  8 + 4096 (serialized verification key with all G1/G2 points)
Total: ~4104 bytes
Rent:  ~0.031 SOL
```

```rust
#[account]
pub struct VerificationKeyAccount {
    pub alpha_g1:    [u8; 64],       // G1 point (uncompressed)
    pub beta_g2:     [u8; 128],      // G2 point (uncompressed)
    pub gamma_g2:    [u8; 128],      // G2 point
    pub delta_g2:    [u8; 128],      // G2 point
    pub ic:          Vec<[u8; 64]>,  // G1 points, length = num_public_inputs + 1
}
```

**VerificationLog (PDA)**

```
Seeds: ["log", verifier_pubkey, nonce]
Size:  8 + 32 (verifier) + 32 (issuer) + 1 (result) + 8 (timestamp) + 32 (proof_hash)
Total: 113 bytes
```

### 3.3 PDA Derivation

All program accounts use Program Derived Addresses (PDAs) to ensure deterministic addressing and program ownership:

```rust
// Issuer account
let (issuer_pda, bump) = Pubkey::find_program_address(
    &[b"issuer", issuer_pubkey.as_ref()],
    &program_id,
);

// Verification key account
let (vk_pda, bump) = Pubkey::find_program_address(
    &[b"vk", issuer_pubkey.as_ref()],
    &program_id,
);
```

### 3.4 Compute Budget Considerations

Solana's default compute budget is 200,000 compute units (CU) per instruction. Groth16 verification using `alt_bn128` pairing operations requires significantly more.

**Estimated compute costs for Groth16 verification:**

| Operation | CU Estimate |
|---|---|
| `alt_bn128_addition` (G1 add) | 500 |
| `alt_bn128_multiplication` (scalar mul) | 12,000 |
| `alt_bn128_pairing` (per pair) | 120,000 |
| Groth16 full verification (3 pairings) | ~360,000 |
| Input deserialization + hashing | ~20,000 |
| Merkle root comparison | ~500 |
| Account reads | ~5,000 |
| **Total** | **~385,000** |

The transaction must request an increased compute budget:

```rust
// Client-side: request compute budget
let compute_ix = ComputeBudgetInstruction::set_compute_unit_limit(400_000);
let priority_ix = ComputeBudgetInstruction::set_compute_unit_price(1); // microlamports
```

**Cost Estimation per Verification:**

```
Base transaction fee:           5,000 lamports (0.000005 SOL)
Priority fee (400k CU * 1uL):  400 lamports
Total per verification:         ~5,400 lamports (~0.0000054 SOL)
At $150/SOL:                    ~$0.00081 per verification
```

### 3.5 Groth16 Verifier Integration on Solana

Solana provides native syscalls for `alt_bn128` (BN254) elliptic curve operations since runtime v1.14. These are critical for on-chain pairing-based proof verification.

**Available Syscalls:**

```
sol_alt_bn128_group_op(
    group_op: u64,        // ADD = 0, MUL = 1, PAIRING = 2
    input: &[u8],
    output: &mut [u8],
) -> u64
```

**Groth16 Verification in Solana Program:**

```rust
pub fn verify_groth16(
    proof: &Proof,
    public_inputs: &[Fr],
    vk: &VerificationKey,
) -> Result<bool> {

    // Step 1: Compute vk_x = vk.ic[0] + sum(public_inputs[i] * vk.ic[i+1])
    let mut vk_x = vk.ic[0];
    for (i, input) in public_inputs.iter().enumerate() {
        let term = bn128_mul(&vk.ic[i + 1], input)?;
        vk_x = bn128_add(&vk_x, &term)?;
    }

    // Step 2: Construct pairing input
    // Verify: e(A, B) == e(alpha, beta) * e(vk_x, gamma) * e(C, delta)
    // Equivalently: e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1
    let neg_a = negate_g1(&proof.a);

    let pairing_input = [
        neg_a,       proof.b,
        vk.alpha_g1, vk.beta_g2,
        vk_x,        vk.gamma_g2,
        proof.c,     vk.delta_g2,
    ];

    // Step 3: Execute pairing check
    let result = bn128_pairing(&pairing_input)?;
    Ok(result == 1)
}
```

The pairing check returns 1 if and only if the product of pairings equals the identity in the target group GT. This is the core of Groth16 verification.

---

## 4. Cryptographic Primitives

### 4.1 Finite Fields

All arithmetic in ZK-DocAuth operates over a prime field `Fp` where:

```
p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
```

This is the scalar field of the BN254 (alt_bn128) elliptic curve. Every credential field, hash output, and circuit wire value is an element of this field. Arithmetic is performed modulo `p`:

```
Addition:       a + b (mod p)
Multiplication: a * b (mod p)
Inversion:      a^(-1) (mod p), computed via Fermat's little theorem: a^(p-2) mod p
```

### 4.2 Elliptic Curves

BN254 defines two groups used in the pairing:

**G1:** Points on `E(Fp): y^2 = x^3 + 3` over `Fp`

**G2:** Points on `E'(Fp2): y^2 = x^3 + 3/(9+u)` over `Fp2` where `Fp2 = Fp[u]/(u^2 + 1)`

Both groups have order:

```
r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
```

Note: For BN254, `r = p` (the scalar field order equals the base field characteristic for this specific curve).

**Generator Points:**

```
G1_generator = (1, 2)
G2_generator = (
    10857046999023057135944570762232829481370756359578518086990519993285655852781 +
    11559732032986387107991004021392285783925812861821192530917403151452391805634 * u,
    8495653923123431417604973247489272438418190587263600148770280649306958101930 +
    4082367875863433681332203403145435568316851327593401208105741076214120093531 * u
)
```

### 4.3 Bilinear Pairings

A bilinear pairing is a map:

```
e: G1 x G2 -> GT
```

satisfying:

```
e(a*P, b*Q) = e(P, Q)^(a*b)      for all a, b in Zr, P in G1, Q in G2
e(P, Q) != 1                       for generators P, Q (non-degeneracy)
```

`GT` is a multiplicative subgroup of `Fp12` of order `r`. The pairing used is the optimal Ate pairing over BN254.

**Why pairings matter for Groth16:** The verification equation requires checking a relationship between proof elements in G1 and G2 that can only be evaluated through pairings. Without pairings, the verifier would need to know the secret trapdoor, defeating zero-knowledge.

### 4.4 zk-SNARKs and Groth16

A zk-SNARK (Zero-Knowledge Succinct Non-Interactive Argument of Knowledge) is a proof system where:

- **Succinct:** Proof size is O(1) -- constant, independent of the computation size.
- **Non-Interactive:** The proof is a single message from prover to verifier.
- **Argument of Knowledge:** A valid proof implies the prover "knows" a valid witness.

**Groth16** (Jens Groth, 2016) is the most widely deployed zk-SNARK scheme. It produces the smallest proofs (192 bytes for BN254) and has the fastest verification (3 pairings + n scalar multiplications where n = number of public inputs).

**Groth16 Proof Structure:**

A proof consists of three group elements:

```
pi = (A, B, C)

where:
    A in G1    (64 bytes uncompressed, 32 bytes compressed)
    B in G2    (128 bytes uncompressed, 64 bytes compressed)
    C in G1    (64 bytes uncompressed, 32 bytes compressed)

Total proof size: 192 bytes (compressed)
```

**Groth16 Verification Equation:**

Given public inputs `x_1, ..., x_l`, verification key `vk = (alpha, beta, gamma, delta, {IC_i})`, and proof `(A, B, C)`:

```
e(A, B) = e(alpha, beta) * e(vk_x, gamma) * e(C, delta)
```

where:

```
vk_x = IC_0 + x_1 * IC_1 + x_2 * IC_2 + ... + x_l * IC_l
```

This is the fundamental equation checked by the on-chain verifier. It holds if and only if the prover knows a valid witness satisfying all circuit constraints.

Equivalently, the verifier checks:

```
e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1_GT
```

This form uses a single multi-pairing call, which is more efficient on Solana.

### 4.5 Trusted Setup

Groth16 requires a per-circuit trusted setup ceremony that produces the proving key `pk` and verification key `vk`. The setup generates secret toxic waste `(tau, alpha, beta, gamma, delta)` that must be destroyed.

**Phase 1 (Powers of Tau):** Generates universal SRS (Structured Reference String) reusable across circuits.

```
{tau^i * G1}_{i=0}^{n-1},  {tau^i * G2}_{i=0}^{n-1}
```

**Phase 2 (Circuit-Specific):** Incorporates the circuit's R1CS constraints to produce `pk` and `vk`.

**Security assumption:** At least one participant in the ceremony must have destroyed their toxic waste. If all participants collude, they can forge proofs.

For ZK-DocAuth, we use the Hermez Network Phase 1 ceremony (54 participants) and conduct a project-specific Phase 2.

### 4.6 Why Groth16 Over Alternatives

| Property | Groth16 | PLONK | STARKs |
|---|---|---|---|
| Proof size | 192 B | ~400 B | 50-200 KB |
| Verification time | 3 pairings | ~20 G1 muls | Hash-intensive |
| Trusted setup | Per-circuit | Universal | None |
| Solana support | Native (alt_bn128) | Requires custom | Too expensive |
| On-chain CU cost | ~385,000 | ~800,000+ | >1,400,000 |
| Post-quantum | No | No | Yes |

**Decision:** Groth16 is selected because:

1. Solana has native BN254 syscalls that make pairing checks cheap.
2. Proof size is minimal, reducing transaction data cost.
3. Verification cost fits within Solana's compute budget with a single `set_compute_unit_limit`.
4. The circuit is fixed (not frequently updated), so per-circuit trusted setup is acceptable.

STARKs are eliminated due to proof size (would exceed Solana's 1232-byte transaction limit). PLONK is viable but has higher on-chain verification cost with no native Solana support for the KZG commitment scheme over BLS12-381.

---

## 5. Commitment Scheme

### 5.1 Poseidon Hash Function

ZK-DocAuth uses the Poseidon hash function (Grassi et al., 2019) for all in-circuit hashing. Poseidon is an algebraic hash function designed natively for prime fields used in ZK circuits.

**Why Poseidon over SHA-256:**

| Property | Poseidon | SHA-256 |
|---|---|---|
| Native field | Fp (BN254 scalar field) | Binary (bit-oriented) |
| R1CS constraints | ~250 per hash | ~27,000 per hash |
| Circuit efficiency | 100x better | Prohibitive for deep trees |
| Security level | 128-bit | 128-bit |
| Input type | Field elements | Byte arrays |

SHA-256 operates on bits and requires boolean decomposition of every byte, generating thousands of constraints for bit rotations and XOR operations. Poseidon operates directly on field elements using only additions and exponentiations in Fp, generating orders of magnitude fewer constraints.

**Poseidon Construction:**

Poseidon uses a sponge construction with a permutation based on:

```
S-box:     x -> x^5 (in Fp)
MDS:       Linear mixing via Maximum Distance Separable matrix
Rounds:    R_F full rounds + R_P partial rounds

For t=3 (2 inputs + 1 capacity), BN254:
    R_F = 8   (full rounds)
    R_P = 57  (partial rounds)
    Total constraints: ~250
```

### 5.2 Credential Commitment Construction

The credential commitment is computed as:

```
name_hash       = Poseidon(field_encode(name))
doc_id_hash     = Poseidon(field_encode(document_id))

credential_hash = Poseidon(
    name_hash,
    dob,
    nationality_code,
    doc_id_hash,
    expiry
)
```

Where `field_encode` converts a variable-length string to a fixed-size field element representation using byte packing (see Section 8.7).

**Collision Resistance:** Poseidon provides 128-bit collision resistance over the BN254 scalar field. Finding two distinct inputs `(x, y)` such that `Poseidon(x) == Poseidon(y)` requires `O(2^128)` operations, which is computationally infeasible.

**Preimage Resistance:** Given `h = Poseidon(x)`, recovering `x` requires `O(2^256)` operations (for a single field element input).

### 5.3 Binding and Hiding Properties

The commitment `credential_hash` is:

- **Binding:** Given a commitment `c`, it is computationally infeasible to find two different credentials `(x, x')` such that `Poseidon(x) = Poseidon(x') = c`. This ensures the prover cannot change their credential after commitment.
- **Hiding (in the ZK context):** The commitment itself does not reveal the underlying credential fields. However, Poseidon is a deterministic hash, so the same input always produces the same output. Hiding is achieved through the zero-knowledge property of the proof system, not the hash function alone.

---

## 6. Merkle Tree Design

### 6.1 Binary Merkle Tree with Poseidon

ZK-DocAuth uses a fixed-depth binary Merkle tree where:

- **Leaf:** `credential_hash` (output of Poseidon commitment)
- **Internal node:** `Poseidon(left_child, right_child)`
- **Depth:** `d = 20` (supports `2^20 = 1,048,576` credentials per issuer)
- **Empty leaf:** `0` (the zero element of Fp)

```
                        root
                       /    \
                     H01      H23
                    /   \    /   \
                  H0    H1  H2    H3
                 / \   / \ / \   / \
                L0 L1 L2 L3 L4 L5 L6 L7

    H0 = Poseidon(L0, L1)
    H01 = Poseidon(H0, H1)
    root = Poseidon(H01, H23)
```

### 6.2 Merkle Inclusion Proof

To prove that a leaf `L` is in the tree with root `R`, the prover provides:

- `leaf`: the credential hash
- `path_elements`: `[s_0, s_1, ..., s_{d-1}]` -- the sibling hashes along the path from leaf to root
- `path_indices`: `[b_0, b_1, ..., b_{d-1}]` -- binary indicators (0 = left, 1 = right) indicating the position of the leaf at each level

**Verification:**

```
current = leaf
for i in 0..d:
    if path_indices[i] == 0:
        current = Poseidon(current, path_elements[i])
    else:
        current = Poseidon(path_elements[i], current)
assert current == root
```

**In-circuit implementation (Circom):**

```circom
template MerkleProof(depth) {
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal output root;

    signal intermediates[depth + 1];
    intermediates[0] <== leaf;

    component hashers[depth];
    component muxes[depth * 2];

    for (var i = 0; i < depth; i++) {
        // Constrain pathIndices to be binary
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        // Select left and right inputs based on path index
        // left  = (1 - pathIndices[i]) * intermediates[i] + pathIndices[i] * pathElements[i]
        // right = pathIndices[i] * intermediates[i] + (1 - pathIndices[i]) * pathElements[i]

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== intermediates[i]
                                  + pathIndices[i] * (pathElements[i] - intermediates[i]);
        hashers[i].inputs[1] <== pathElements[i]
                                  + pathIndices[i] * (intermediates[i] - pathElements[i]);
        intermediates[i + 1] <== hashers[i].out;
    }

    root <== intermediates[depth];
}
```

### 6.3 Complexity Analysis

- **Tree construction:** `O(n)` hashes for `n` leaves.
- **Proof size:** `O(d) = O(log n)` field elements. For `d = 20`, the Merkle path consists of 20 sibling hashes (20 * 32 = 640 bytes).
- **Verification (in-circuit):** `d` Poseidon hashes = `d * 250 = 5,000` constraints for depth 20.
- **Verification (on-chain):** Constant time -- the circuit computes the root and the verifier only checks the final pairing equation.

### 6.4 Formal Merkle Verification

For a tree of depth `d` with leaves `L_0, ..., L_{2^d - 1}`:

```
Layer 0 (leaves):   N_{0,i} = L_i
Layer k:            N_{k,i} = Poseidon(N_{k-1, 2i}, N_{k-1, 2i+1})
Root:               R = N_{d, 0}
```

A Merkle proof for leaf `L_j` consists of siblings along the path:

```
s_k = N_{k, j_k XOR 1}    where j_k = floor(j / 2^k) mod 2
```

The verifier reconstructs:

```
h_0 = L_j
h_{k+1} = Poseidon(h_k, s_k)     if j_k = 0
h_{k+1} = Poseidon(s_k, h_k)     if j_k = 1
```

Accept if `h_d == R`.

---

## 7. Revocation Mechanism

### 7.1 Design Options

**Option A: Valid Credentials Tree (Inclusion-based)**

Maintain a Merkle tree of all valid credential hashes. Proving non-revocation requires proving inclusion in this tree.

| Pros | Cons |
|---|---|
| Simple proof of validity | Entire tree rebuilt on revocation |
| Single Merkle proof | Root changes on every revocation |
| | All users must update their Merkle paths |

**Option B: Revoked Credentials Tree (Exclusion-based)**

Maintain a separate Merkle tree of revoked credential hashes. Proving non-revocation requires proving non-inclusion (i.e., the credential is NOT in the revoked tree).

| Pros | Cons |
|---|---|
| Revocation is append-only | Non-membership proofs are complex |
| Existing users' paths unchanged | Requires sparse Merkle tree or accumulator |
| Efficient for low revocation rate | Higher constraint count |

### 7.2 Selected Approach: Dual-Root Model

ZK-DocAuth uses **Option A** with an optimization: the Issuer maintains the valid credentials tree and publishes two roots:

```
IssuerAccount {
    merkle_root:     [u8; 32],    // Root of valid credentials tree
    revocation_root: [u8; 32],    // Root of revocation epoch tree (for freshness)
}
```

When a credential is revoked:

1. The Issuer removes the leaf from the valid credentials tree (replaces with zero).
2. Recomputes the root.
3. Calls `update_merkle_root` on-chain with the new root.
4. Increments the revocation epoch counter.

Non-revoked users must periodically fetch updated Merkle paths from the Issuer's off-chain service.

### 7.3 On-chain Root Update

```rust
pub fn update_merkle_root(
    ctx: Context<UpdateMerkleRoot>,
    new_root: [u8; 32],
    tree_size: u64,
) -> Result<()> {
    let issuer = &mut ctx.accounts.issuer_account;
    require!(
        ctx.accounts.authority.key() == issuer.authority,
        ErrorCode::Unauthorized
    );
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
```

---

## 8. Circuit Definition

### 8.1 Full Circuit Specification

The ZK-DocAuth circuit proves the following statement:

> "I possess a credential whose hash is a leaf in the Merkle tree with root `merkle_root`, AND the credential satisfies the requested predicate (age, nationality, expiry), AND the credential has not been revoked."

### 8.2 Signal Declarations

```circom
template ZKDocAuth(merkleDepth) {
    // ---- Private Inputs (Witness) ----
    signal private input name;               // Field-encoded name
    signal private input dob;                // YYYYMMDD as integer
    signal private input nationality;        // ISO 3166-1 numeric code
    signal private input document_id;        // Field-encoded document ID
    signal private input expiry;             // YYYYMMDD as integer
    signal private input merkle_path[merkleDepth];
    signal private input merkle_indices[merkleDepth];

    // ---- Public Inputs ----
    signal input merkle_root;
    signal input current_date;               // YYYYMMDD as integer
    signal input min_age;                    // Minimum age requirement
    signal input expected_nationality_hash;  // Poseidon(expected_nationality_code)

    // ---- Output ----
    signal output valid;
}
```

### 8.3 Constraint Block 1: Credential Hash Computation

```circom
// Compute name_hash = Poseidon(name)
component name_hasher = Poseidon(1);
name_hasher.inputs[0] <== name;

// Compute doc_id_hash = Poseidon(document_id)
component doc_hasher = Poseidon(1);
doc_hasher.inputs[0] <== document_id;

// Compute credential_hash = Poseidon(name_hash, dob, nationality, doc_id_hash, expiry)
component cred_hasher = Poseidon(5);
cred_hasher.inputs[0] <== name_hasher.out;
cred_hasher.inputs[1] <== dob;
cred_hasher.inputs[2] <== nationality;
cred_hasher.inputs[3] <== doc_hasher.out;
cred_hasher.inputs[4] <== expiry;
```

### 8.4 Constraint Block 2: Merkle Inclusion

```circom
component merkle_verifier = MerkleProof(merkleDepth);
merkle_verifier.leaf <== cred_hasher.out;
for (var i = 0; i < merkleDepth; i++) {
    merkle_verifier.pathElements[i] <== merkle_path[i];
    merkle_verifier.pathIndices[i] <== merkle_indices[i];
}

// Enforce: computed root == public merkle_root
merkle_verifier.root === merkle_root;
```

### 8.5 Constraint Block 3: Age Verification

```circom
// Extract year from dob (dob = YYYYMMDD, year = dob / 10000)
signal dob_year;
dob_year <-- dob \ 10000;  // Integer division (witness computation)

// Constrain: dob == dob_year * 10000 + remainder, 0 <= remainder < 10000
signal dob_remainder;
dob_remainder <== dob - dob_year * 10000;
// Range check remainder is in [0, 9999] -- see Section 10

// Extract year from current_date
signal current_year;
current_year <-- current_date \ 10000;
signal current_remainder;
current_remainder <== current_date - current_year * 10000;

// Compute age (conservative: year difference only)
signal age;
age <== current_year - dob_year;

// Enforce: age >= min_age
// Equivalently: age - min_age >= 0
// Implemented via range proof (see Section 10)
component age_check = GreaterEqThan(8);  // 8-bit range: supports ages 0-255
age_check.in[0] <== age;
age_check.in[1] <== min_age;
age_check.out === 1;
```

### 8.6 Constraint Block 4: Nationality Verification

```circom
// Compute hash of claimed nationality
component nat_hasher = Poseidon(1);
nat_hasher.inputs[0] <== nationality;

// Enforce: hash(nationality) == expected_nationality_hash
nat_hasher.out === expected_nationality_hash;
```

### 8.7 Constraint Block 5: Document Expiry

```circom
// Extract expiry year
signal expiry_year;
expiry_year <-- expiry \ 10000;
signal expiry_remainder;
expiry_remainder <== expiry - expiry_year * 10000;

// Enforce: expiry > current_date
// Equivalently: expiry - current_date > 0, i.e., expiry - current_date - 1 >= 0
component expiry_check = GreaterEqThan(32);
expiry_check.in[0] <== expiry;
expiry_check.in[1] <== current_date + 1;
expiry_check.out === 1;
```

### 8.8 String-to-Field Encoding

Strings (names, document IDs) must be converted to field elements before entering the circuit. The encoding strategy:

**Byte Packing:**

```
Given string s = "YASH KUMAR" (10 bytes in UTF-8)

bytes = [89, 65, 83, 72, 32, 75, 85, 77, 65, 82]

field_element = sum(bytes[i] * 256^i for i in 0..len(bytes))
             = 89 + 65*256 + 83*256^2 + ... + 82*256^9
```

For strings longer than 31 bytes (max field element size in BN254), the string is split into 31-byte chunks, each packed into a field element, and then hashed together:

```
field_encode(s):
    if len(s) <= 31:
        return pack_bytes(s)
    else:
        chunks = split(s, 31)
        packed = [pack_bytes(c) for c in chunks]
        return Poseidon(packed...)
```

This encoding is injective (collision-free) for strings up to 31 bytes and collision-resistant (via Poseidon) for longer strings.

---

## 9. R1CS Representation

### 9.1 Rank-1 Constraint System

Every arithmetic circuit compiles to an R1CS -- a system of constraints of the form:

```
(a . w) * (b . w) = (c . w)
```

where `w` is the witness vector (all signals including public inputs, private inputs, and intermediate values) and `a`, `b`, `c` are coefficient vectors. The dot product `a . w` is a linear combination of witness elements.

Equivalently, for `m` constraints and `n` witness elements:

```
(A * w) o (B * w) = C * w
```

where `A`, `B`, `C` are `m x n` matrices and `o` denotes the Hadamard (element-wise) product.

### 9.2 Constraint Examples

**Equality Constraint:** `x == y`

```
Rewritten as: x - y = 0
R1CS form: (1) * (x - y) = 0
    a = [0, ..., 1, ..., -1, ..., 0]   (1 at position of x, -1 at position of y)
    b = [1, 0, ..., 0]                  (constant 1)
    c = [0, 0, ..., 0]                  (zero)
```

**Multiplication Constraint:** `z = x * y`

```
R1CS form: (x) * (y) = z
    a = [0, ..., 1, ..., 0]   (1 at position of x)
    b = [0, ..., 1, ..., 0]   (1 at position of y)
    c = [0, ..., 1, ..., 0]   (1 at position of z)
```

**Boolean Constraint:** `b in {0, 1}`

```
Rewritten as: b * (1 - b) = 0
R1CS form: (b) * (1 - b) = 0
    a = [0, ..., 1, ..., 0]   (1 at position of b)
    b = [1, ..., -1, ..., 0]  (constant 1 minus position of b)
    c = [0, 0, ..., 0]
```

**Addition Constraint:** `z = x + y`

```
Not directly an R1CS constraint (no multiplication).
Rewritten as: (x + y) * (1) = z
    a = [0, ..., 1, ..., 1, ..., 0]
    b = [1, 0, ..., 0]
    c = [0, ..., 1, ..., 0]     (1 at position of z)
```

### 9.3 Greater-Than as R1CS

The constraint `a >= b` cannot be expressed as a single R1CS constraint. It requires decomposition:

```
diff = a - b                     // must be non-negative
bits = binary_decomposition(diff, n)   // decompose into n bits

// Constrain each bit to be boolean:
for i in 0..n:
    bits[i] * (1 - bits[i]) = 0

// Constrain reconstruction:
sum(bits[i] * 2^i for i in 0..n) = diff
```

This generates `n + 1` constraints for an `n`-bit range proof. For age verification with 8-bit range, this adds 9 constraints.

---

## 10. Range Proof Logic

### 10.1 Problem Statement

The circuit must enforce `age >= 18` without revealing the exact age. Since R1CS only supports equality and multiplication, inequality must be reduced to bit-level operations.

### 10.2 Bit Decomposition Approach

To prove `x >= 0` for an `n`-bit value `x`:

1. Decompose `x` into bits `b_0, b_1, ..., b_{n-1}`:

```
x = sum(b_i * 2^i)    for i = 0 to n-1
```

2. Constrain each bit to be boolean:

```
b_i * (1 - b_i) = 0    for all i
```

3. The reconstruction constraint ensures `x` is in `[0, 2^n - 1]`.

To prove `a >= b`, prove that `a - b >= 0` by decomposing `a - b` into bits:

```
diff = a - b
diff = sum(bit_i * 2^i)
bit_i * (1 - bit_i) = 0 for all i
```

If `a - b` is negative (i.e., `a < b`), there exists no valid boolean decomposition because `a - b + p` (reduced mod `p`) would require more than `n` bits to represent.

### 10.3 Constraint Complexity

For an `n`-bit range proof:

| Component | Constraints |
|---|---|
| Bit decomposition (`n` boolean constraints) | `n` |
| Reconstruction (1 linear constraint) | `1` |
| **Total** | `n + 1` |

For `age >= 18` with 8-bit decomposition: **9 constraints**.

### 10.4 GreaterEqThan Circuit Template

```circom
template GreaterEqThan(n) {
    signal input in[2];    // in[0] >= in[1]
    signal output out;     // 1 if true, 0 if false

    signal diff;
    diff <== in[0] - in[1];

    // Decompose diff into n bits
    signal bits[n];
    var sum = 0;
    for (var i = 0; i < n; i++) {
        bits[i] <-- (diff >> i) & 1;
        bits[i] * (1 - bits[i]) === 0;
        sum += bits[i] * (1 << i);
    }

    // Reconstruction check
    diff === sum;

    out <== 1;
}
```

Note: This template enforces `in[0] >= in[1]` as a hard constraint (the circuit is unsatisfiable if `in[0] < in[1]`). The `out` signal is always 1 when the circuit is satisfiable.

### 10.5 Security Note on Range Proofs

The bit-length `n` must be chosen carefully. If `n` is too large (approaching `log2(p)`), the prover could encode a negative value as `p - |diff|`, which wraps around the field. For practical values (ages 0--255, dates 0--99999999), `n = 32` is sufficient and safe since `2^32 << p`.

---

## 11. Folder Structure

```
zk-doc-auth-solana/
│
├── lib/                                  # Flutter/Dart client application
│   ├── core/
│   │   ├── constants.dart                # RPC URLs, program ID, PDA seeds, BN254 field params
│   │   ├── exceptions.dart               # Typed exception hierarchy (8 sealed classes)
│   │   └── utils.dart                    # Field encoding, byte conversions, date helpers
│   ├── models/
│   │   └── models.dart                   # Credential, Groth16Proof, G1/G2Point, MerkleProofData
│   ├── crypto/
│   │   ├── poseidon.dart                 # Pure-Dart Poseidon hash (BN254 scalar field)
│   │   ├── poseidon_constants.dart       # Round constants & MDS matrices (t=2,3,6)
│   │   └── merkle_tree.dart             # Binary Merkle tree (depth 20, Poseidon nodes)
│   ├── services/
│   │   ├── credential_service.dart       # Issuance, storage (FlutterSecureStorage), commitment
│   │   ├── proof_service.dart            # Witness construction, constraint validation, Groth16 prover
│   │   └── solana_service.dart           # RPC client, PDA derivation, transaction builder
│   ├── providers/
│   │   └── providers.dart                # ChangeNotifier state management (Credential/Proof/Solana)
│   ├── ui/
│   │   ├── theme.dart                    # Dark theme, gradient cards, purple/teal palette
│   │   └── widgets.dart                  # StatusBadge, InfoRow, LoadingButton, HashDisplay
│   ├── screens/
│   │   ├── home_screen.dart              # Landing page with 4 feature cards
│   │   ├── credential_screen.dart        # Form-based credential issuance
│   │   ├── proof_screen.dart             # Claim type selection + ZK proof generation
│   │   ├── verify_screen.dart            # On-chain proof submission + 5-step pipeline
│   │   └── merkle_screen.dart            # Merkle tree explorer with ASCII diagram
│   └── main.dart                         # App entry point (MultiProvider + named routes)
│
├── solana_program/                        # On-chain Anchor/Rust program
│   ├── programs/
│   │   └── zk-doc-auth/
│   │       ├── src/
│   │       │   ├── lib.rs                # Anchor program (5 instructions + contexts)
│   │       │   ├── state.rs              # IssuerAccount, VerificationKeyAccount, NullifierAccount
│   │       │   ├── errors.rs             # ZKDocAuthError enum (11 variants, codes 6000-6010)
│   │       │   ├── events.rs             # IssuerInitialized, MerkleRootUpdated, ProofVerified
│   │       │   └── verifier.rs           # Groth16 verification via alt_bn128 syscalls
│   │       ├── Cargo.toml
│   │       └── Xargo.toml
│   ├── Anchor.toml
│   └── Cargo.toml
│
├── circuits/                              # Circom ZK circuits
│   ├── src/
│   │   └── zk_doc_auth.circom           # Main circuit (~25K constraints, depth-20 Merkle)
│   ├── scripts/
│   │   ├── compile.js                    # circom compilation
│   │   ├── setup.js                      # Groth16 trusted setup (PoT + Phase 2)
│   │   ├── generate_input.js             # Input JSON generator with Poseidon hashing
│   │   ├── generate_witness.js           # Witness computation
│   │   ├── prove.js                      # Groth16 proof generation
│   │   └── verify.js                     # Off-chain verification
│   ├── inputs/
│   │   └── sample_input.json             # Example witness input
│   ├── build/                            # Generated artifacts (gitignored)
│   └── package.json
│
├── pubspec.yaml                           # Flutter dependencies
├── README.md
└── .gitignore
```

---

## 12. Tooling Stack

### 12.1 Core Dependencies

| Tool | Version | Purpose |
|---|---|---|
| **Flutter** | 3.x | Cross-platform client (mobile + web) |
| **Dart** | 3.x | Client language, Poseidon hash, Merkle tree |
| Anchor | 0.30+ | Solana program framework |
| Solana CLI | 1.18+ | Cluster interaction, key management |
| Circom | 2.1+ | Arithmetic circuit compiler |
| snarkjs | 0.7+ | Trusted setup, proof generation, verification |
| Node.js | 18+ | Circuit tooling runtime |
| Rust | 1.75+ | On-chain program development |
| circomlib | 2.0+ | Poseidon, comparator, mux circuit templates |

### 12.2 Flutter Dependencies

| Package | Purpose |
|---|---|
| `provider` | State management (ChangeNotifier pattern) |
| `solana_web3` | Solana RPC & transaction types |
| `pointycastle` | BigInt arithmetic, field operations |
| `flutter_secure_storage` | Encrypted credential storage |
| `crypto` / `convert` | Hashing, encoding utilities |
| `bip39` / `ed25519_hd_key` | Wallet key derivation |
| `bs58` / `hex` | Base58/hex encoding for Solana |
| `uuid` | Unique identifiers |

### 12.3 Optional / Advanced

| Tool | Purpose |
|---|---|
| arkworks (Rust) | Alternative prover implementation in Rust for mobile/embedded |
| rapidsnark | C++ prover for faster proof generation |
| ffjavascript | Finite field arithmetic in JavaScript |
| circomlibjs | JS Poseidon hash for input generation scripts |

### 12.4 Full Development Flow

**Step 1: Set up the Flutter client**

```bash
cd zk_kyc
flutter pub get
flutter run          # Launch on connected device / emulator
```

**Step 2: Compile the Circuit**

```bash
cd circuits
npm install
npm run compile      # circom -> R1CS + WASM
```

**Step 3: Trusted Setup**

```bash
npm run setup        # Powers of Tau + Phase-2 (one-time)
```

**Step 4: Generate Input, Witness, and Proof**

```bash
node scripts/generate_input.js   # Generate input.json from credential data
npm run witness                   # Compute witness
npm run prove                     # Generate Groth16 proof
npm run verify                    # Off-chain verification check
```

**Step 5: Build and Deploy Solana Program**

```bash
cd solana_program
anchor build
anchor deploy --provider.cluster devnet
```

**Step 6: Run Flutter App and Submit Proof On-Chain**

The Flutter app handles the full user flow:
1. **Issue Credential** — Enter KYC fields, compute Poseidon commitment, insert into Merkle tree.
2. **Generate ZK Proof** — Select claim type (age, nationality, expiry), generate Groth16 proof locally.
3. **On-Chain Verification** — Submit proof to Solana program, which verifies via `alt_bn128` pairing check.
4. **Merkle Explorer** — Inspect tree state, verify inclusion proofs, view complexity analysis.

```bash
flutter run    # Starts the app with all 4 screens accessible from the home page
```

---

## 13. Step-by-Step Proof Flow

### 13.1 Issuance Phase

```
1. User submits identity document to Issuer (off-chain, secure channel).
         |
         v
2. Issuer verifies document authenticity (OCR, NFC, database lookup).
         |
         v
3. Issuer extracts structured fields: {name, dob, nationality, document_id, expiry}.
         |
         v
4. Issuer computes credential_hash = Poseidon(Poseidon(name), dob, nationality,
                                               Poseidon(document_id), expiry).
         |
         v
5. Issuer inserts credential_hash as leaf at index i in the Merkle tree.
         |
         v
6. Issuer recomputes Merkle root.
         |
         v
7. Issuer calls update_merkle_root(new_root, tree_size) on Solana.
         |
         v
8. Issuer sends to User: {credential, merkle_path, merkle_indices, leaf_index,
                           issuer_signature}.
```

### 13.2 Proof Generation Phase

```
1. User loads credential and Merkle path from local encrypted storage.
         |
         v
2. User constructs witness = {name, dob, nationality, document_id, expiry,
                               merkle_path, merkle_indices}.
         |
         v
3. User constructs public inputs = {merkle_root, current_date, min_age,
                                      expected_nationality_hash}.
         |
         v
4. User invokes snarkjs/WASM prover:
   proof = groth16.fullProve(witness, circuit.wasm, proving_key.zkey)
         |
         v
5. Proof output: {A: G1, B: G2, C: G1} -- 192 bytes total.
         |
         v
6. User serializes proof + public inputs into Solana transaction instruction data.
```

### 13.3 Verification Phase

```
1. User submits transaction to Solana with instruction:
   verify_proof(proof, public_inputs, issuer_pda)
         |
         v
2. Solana program deserializes proof (A, B, C) and public inputs.
         |
         v
3. Program loads IssuerAccount PDA and reads stored merkle_root.
         |
         v
4. Program checks: public_inputs.merkle_root == issuer_account.merkle_root.
   If mismatch, return Err(InvalidMerkleRoot).
         |
         v
5. Program loads VerificationKeyAccount PDA, reads VK points.
         |
         v
6. Program computes vk_x = IC[0] + sum(public_inputs[i] * IC[i+1]).
   (Uses alt_bn128 scalar multiplication and addition syscalls.)
         |
         v
7. Program executes pairing check:
   e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1_GT
   (Single alt_bn128 pairing syscall with 4 pairs.)
         |
         v
8. If pairing check returns 1: emit ProofVerified event, return Ok(()).
   If pairing check returns 0: return Err(InvalidProof).
```

---

## 14. Security Analysis

### 14.1 Soundness

An adversary without a valid credential cannot produce a proof that the verifier accepts. Formally, for any probabilistic polynomial-time adversary A:

```
Pr[Verify(vk, x, pi) = 1 AND x is false] <= negl(lambda)
```

This relies on the q-type knowledge assumption over BN254 and the hardness of the discrete logarithm problem in G1 and G2.

**Concrete security:** BN254 provides approximately 100 bits of security against known attacks (including the Kim-Barbulescu tower NFS improvement). This is considered sufficient for most applications but is below the 128-bit target. Migration to BLS12-381 (128 bits) or BN382 is recommended for long-term deployments.

### 14.2 Completeness

An honest prover with a valid credential can always generate a proof that the verifier accepts. This is guaranteed by the correctness of the Groth16 construction: if the witness satisfies all R1CS constraints, the resulting proof elements `(A, B, C)` will satisfy the verification equation.

### 14.3 Zero-Knowledge Property

The proof reveals nothing about the private inputs (name, dob, nationality, document_id, expiry, Merkle path) beyond the truth of the public statement. Formally, there exists a simulator S that, given only the public inputs and the verification key, can produce proofs indistinguishable from real proofs.

The simulation is possible because of the randomization in proof generation: the prover selects random `r, s` in Zr and uses them to blind the proof elements:

```
A = (1/delta) * (alpha + sum(a_i * w_i * tau^i) + r * delta) * G1
B = (1/delta) * (beta  + sum(b_i * w_i * tau^i) + s * delta) * G2
C = ... + s*A + r*B - r*s*delta
```

The random blinding factors `r, s` ensure that the proof distribution is independent of the witness.

### 14.4 Trusted Setup Risks

**Threat:** If all participants in the trusted setup ceremony collude and retain their toxic waste, they can forge proofs for any statement.

**Mitigation:**
- Use a multi-party computation (MPC) ceremony with geographically distributed participants.
- Minimum 10 participants from independent organizations.
- Publish ceremony transcripts for public verification.
- The 1-of-N honest participant assumption: security holds if at least one participant destroyed their contribution.

**Impact of compromise:** An attacker with the trapdoor can create valid proofs for non-existent credentials. They cannot, however, read private inputs from existing proofs (zero-knowledge is unconditional in the random oracle model).

### 14.5 Issuer Trust Assumptions

The Issuer is a trusted party in the protocol. Specifically:

- The Issuer can issue credentials for non-existent identities (Sybil attack).
- The Issuer can refuse to revoke compromised credentials.
- The Issuer can insert arbitrary leaves into the Merkle tree.

**Mitigation:**
- Issuer registration requires governance approval (multisig or DAO vote).
- Issuer behavior is auditable: Merkle root updates are logged on-chain with timestamps.
- Multiple Issuers can be supported; verifiers can whitelist specific Issuers.
- Future work: decentralized Issuer network with stake-based accountability.

### 14.6 Replay Attack Mitigation

**Threat:** An attacker intercepts a valid proof and resubmits it.

**Mitigation Strategies:**

1. **Nonce binding:** Include a unique nonce (from the verifier) as a public input. The circuit constrains `Poseidon(credential_hash, nonce) == expected_binding`. Each proof is bound to a specific verification session.

2. **Timestamp freshness:** The `current_date` public input must be within an acceptable window (e.g., today +/- 1 day). The verifier checks this on-chain.

3. **Proof nullifier:** The circuit outputs a deterministic nullifier `nullifier = Poseidon(credential_hash, domain_separator)`. The on-chain program maintains a set of used nullifiers and rejects duplicates.

### 14.7 Front-Running Considerations

**Threat:** A validator or MEV searcher observes a pending proof transaction in the mempool and extracts the proof to submit their own transaction claiming the verification result.

**Mitigation:**
- Bind the proof to the submitter's public key by including `submitter_pubkey` as a public input.
- The circuit constrains that the proof is only valid for the specified submitter.
- On-chain: `require!(public_inputs.submitter == ctx.accounts.submitter.key())`.

### 14.8 Proof Reuse Risks

**Threat:** A user generates one proof and uses it across multiple verifiers or contexts.

**Mitigation:**
- Domain separation: include a `verifier_id` or `context` field as a public input.
- Time-limited proofs: include `proof_expiry` as a public input, checked on-chain.
- Nullifier per domain: `nullifier = Poseidon(credential_hash, verifier_id)`.

---

## 15. Performance Analysis

### 15.1 Constraint Count Estimation

| Component | Constraints |
|---|---|
| Poseidon hash (name) | ~250 |
| Poseidon hash (document_id) | ~250 |
| Poseidon hash (credential, 5 inputs) | ~500 |
| Merkle proof (depth 20, 20 Poseidon) | ~5,000 |
| Nationality hash + equality check | ~255 |
| Age range proof (8-bit) | ~10 |
| Expiry range proof (32-bit) | ~35 |
| Date decomposition constraints | ~20 |
| Miscellaneous (wiring, mux) | ~200 |
| **Total** | **~6,520** |

### 15.2 Proof Generation Time

Proof generation is performed client-side. Benchmarks for ~6,500 constraints on BN254:

| Platform | Prover | Time |
|---|---|---|
| Desktop (x86_64, 16 GB RAM) | snarkjs (WASM) | ~3.5 seconds |
| Desktop (x86_64, 16 GB RAM) | rapidsnark (C++) | ~0.8 seconds |
| Mobile (ARM64, 4 GB RAM) | snarkjs (WASM) | ~8 seconds |
| Mobile (ARM64, 4 GB RAM) | arkworks (Rust/native) | ~2.5 seconds |

Key generation (one-time):
- Proving key size: ~8 MB (for 6,500 constraints)
- Verification key size: ~1.5 KB

### 15.3 Verification Cost (On-chain)

| Operation | Compute Units |
|---|---|
| Instruction deserialization | ~2,000 |
| Account loading (3 accounts) | ~6,000 |
| Public input scalar multiplications (4 inputs, ~12,000 each) | ~48,000 |
| G1 additions (5 additions) | ~2,500 |
| Multi-pairing (4 pairs) | ~320,000 |
| Merkle root comparison | ~200 |
| Event emission | ~2,000 |
| **Total** | **~380,700** |

Within the 400,000 CU budget requested via `ComputeBudgetInstruction`.

### 15.4 Scalability Analysis

**Throughput:** Each verification consumes one transaction. Solana processes ~4,000 TPS on mainnet. Assuming 10% of slots are available for ZK-DocAuth verifications, the system supports ~400 verifications per second.

**State growth:** Each Issuer account is 185 bytes. Each verification log is 113 bytes. At 1 million verifications, log storage is ~113 MB. Logs can be pruned or stored off-chain with only hashes on-chain.

**Merkle tree scaling:** Depth 20 supports 1M credentials per Issuer. Increasing to depth 32 supports 4 billion credentials at a cost of 12 additional Poseidon hashes in-circuit (~3,000 more constraints). Proof generation time increases by approximately 40%.

**Multi-Issuer:** Each Issuer has independent state (PDA-isolated). Adding Issuers does not affect verification cost. The verifier simply loads the appropriate Issuer PDA based on the `issuer_pubkey` provided in the instruction.

---

## 16. Real World Use Cases

### 16.1 ZK-KYC for Centralized and Decentralized Exchanges

Exchanges can verify that a user has completed KYC with a licensed provider without receiving any PII. The user proves `credential_valid AND age >= 18 AND nationality NOT IN sanctioned_list`. The exchange stores only the proof hash and verification result, satisfying compliance requirements while holding zero PII (dramatically reducing breach liability).

### 16.2 DAO Voting Eligibility

DAOs requiring one-person-one-vote can use ZK-DocAuth to prove that each voter holds a unique, valid identity credential without linking votes to real-world identities. The nullifier mechanism ensures each credential can only vote once per proposal.

### 16.3 Age-Restricted Access

Content platforms, alcohol delivery services, and regulated applications can verify `age >= 21` (or any threshold) without learning the user's exact date of birth, name, or any other field. The proof is generated locally on the user's device.

### 16.4 Cross-Border Compliance

Financial institutions operating across jurisdictions can verify nationality-based compliance rules (e.g., FATF travel rule, OFAC screening) without collecting passport scans. The user proves `nationality NOT IN {sanctioned_countries}` via set membership proof, and the institution logs only the cryptographic verification result.

### 16.5 Anonymous Nationality Proof

Humanitarian organizations, refugee systems, or cross-border labor platforms can verify nationality for eligibility without compromising the individual's privacy. The proof reveals only that `nationality == X` for a specific X, without exposing any other credential field.

### 16.6 Credential-Gated DeFi

DeFi protocols requiring regulatory compliance can gate access to specific pools or products based on verified credentials. Users prove eligibility on-chain, and the smart contract enforces access control based on proof validity, without any off-chain KYC data transfer.

---

## 17. Future Work

### 17.1 PLONK Migration

Groth16's per-circuit trusted setup is a deployment friction point. Migrating to PLONK (or its variants: TurboPlonk, UltraPlonk) would enable a universal trusted setup reusable across all circuit revisions. This requires:

- Implementing a KZG-based polynomial commitment verifier on Solana (currently no native support).
- Evaluating BLS12-381 syscall availability on Solana.
- Accepting higher verification cost (~2x) in exchange for setup universality.

### 17.2 Recursive Proof Composition

Recursive SNARKs (e.g., using Nova, Halo2, or Groth16-in-Groth16) would allow batch verification: a single proof attesting to the validity of N individual proofs. This enables:

- Aggregating multiple credential checks into one on-chain verification.
- Reducing per-user verification cost to `O(1/N)`.
- Supporting complex multi-credential policies (e.g., "has KYC from Issuer A AND credit score from Issuer B").

### 17.3 Mobile Proof Generation (Production Prover Integration)

The Flutter app currently includes a simulated Groth16 prover. Integrating a real prover for production use requires:

- **Platform Channel Bridge:** Invoke the snarkjs WASM prover (or native rapidsnark/arkworks binary) from Dart via Flutter platform channels (MethodChannel).
- **WASM in WebView:** For Flutter Web, load snarkjs directly in a JavaScript interop context.
- **Native FFI:** Compile arkworks-rs Groth16 prover to native ARM64/x86 and call via `dart:ffi` for sub-3-second mobile proving.
- **Proving Key Distribution:** Bundle or lazily download the ~8 MB `.zkey` file as an app asset.
- Investigate GPU-accelerated proving on mobile (Metal for iOS, Vulkan for Android).

### 17.4 Decentralized Issuer Network

Replace the single-Issuer trust model with a federated or fully decentralized Issuer network:

- Issuers stake SOL or governance tokens as collateral.
- Misbehavior (issuing fraudulent credentials) is penalized via slashing.
- Multiple Issuers can attest to the same credential, increasing trust via threshold.
- Issuer reputation scores are maintained on-chain.

### 17.5 Multi-Attribute Selective Disclosure

Extend the circuit to support selective disclosure of arbitrary subsets of credential fields. Instead of a single fixed circuit for `age + nationality`, deploy a parametric circuit where the user selects which predicates to prove at proof generation time. This requires:

- A more general circuit with conditional constraint activation.
- OR-composition of Groth16 proofs (using disjunctive proof techniques).
- Potentially larger circuit but significantly more flexible.

### 17.6 Cross-Chain Verification

Deploy verification contracts on EVM chains (Ethereum, Polygon, Arbitrum) alongside the Solana program. Proofs generated once can be verified on any supported chain. This requires:

- Standardized proof serialization format.
- EVM Groth16 verifier (well-established via Solidity pairing precompiles at address 0x06, 0x07, 0x08).
- Cross-chain state synchronization for Merkle roots (via oracle or bridge).

### 17.7 Formal Verification

Apply formal methods to verify:

- Circuit correctness: all constraints faithfully encode the intended policy.
- Solana program correctness: the on-chain verifier correctly implements the Groth16 verification equation.
- No under-constrained signals: using tools like Circom's `--inspect` flag, Ecne, or Picus.
- Pairing arithmetic correctness: verify alt_bn128 syscall usage against reference implementations.

---

## Appendix A: Proof Data Format

### On-chain Instruction Data Layout

```
Byte offset   Field                Size (bytes)   Description
-----------   -----                -----------    -----------
0             instruction_id       1              Discriminator (verify = 0x03)
1             proof.a_x            32             G1.x coordinate (big-endian)
33            proof.a_y            32             G1.y coordinate
65            proof.b_x_c0         32             G2.x real component
97            proof.b_x_c1         32             G2.x imaginary component
129           proof.b_y_c0         32             G2.y real component
161           proof.b_y_c1         32             G2.y imaginary component
193           proof.c_x            32             G1.x coordinate
225           proof.c_y            32             G1.y coordinate
257           merkle_root          32             Public input 1
289           current_date         8              Public input 2 (u64)
297           min_age              8              Public input 3 (u64)
305           nationality_hash     32             Public input 4
-----------
Total:        337 bytes
```

### Account Keys (passed via instruction accounts)

```
Index   Account               Signer   Writable   Description
-----   -------               ------   --------   -----------
0       submitter             Yes      Yes        Fee payer, proof submitter
1       issuer_account (PDA)  No       No         IssuerAccount with merkle_root
2       vk_account (PDA)      No       No         VerificationKeyAccount
3       system_program        No       No         System program
```

---

## Appendix B: Error Codes

```rust
#[error_code]
pub enum ZKDocAuthError {
    #[msg("Proof verification failed: pairing check returned false")]
    InvalidProof,              // 6000

    #[msg("Merkle root in proof does not match on-chain root")]
    InvalidMerkleRoot,         // 6001

    #[msg("Issuer account is not active")]
    IssuerInactive,            // 6002

    #[msg("Caller is not the authorized issuer")]
    Unauthorized,              // 6003

    #[msg("Invalid proof data format")]
    MalformedProof,            // 6004

    #[msg("Public input count does not match verification key")]
    InputCountMismatch,        // 6005

    #[msg("G1 point is not on the curve")]
    InvalidG1Point,            // 6006

    #[msg("G2 point is not on the curve")]
    InvalidG2Point,            // 6007

    #[msg("Proof nullifier has already been used")]
    NullifierAlreadyUsed,      // 6008

    #[msg("Proof has expired")]
    ProofExpired,              // 6009
}
```

---

## Appendix C: References

1. Groth, J. (2016). "On the Size of Pairing-based Non-interactive Arguments." EUROCRYPT 2016. https://eprint.iacr.org/2016/260
2. Grassi, L., Khovratovich, D., Rechberger, C., Roy, A., Schofnegger, M. (2019). "Poseidon: A New Hash Function for Zero-Knowledge Proof Systems." USENIX Security 2021. https://eprint.iacr.org/2019/458
3. Ben-Sasson, E., et al. (2014). "Succinct Non-Interactive Zero Knowledge for a von Neumann Architecture." USENIX Security 2014.
4. Solana Foundation. "alt_bn128 Syscalls." https://docs.solanalabs.com/runtime/programs
5. iden3. "Circom 2 Documentation." https://docs.circom.io/
6. iden3. "snarkjs." https://github.com/iden3/snarkjs
7. Ethereum Foundation. "EIP-196: Precompiled contracts for elliptic curve operations on alt_bn128." https://eips.ethereum.org/EIPS/eip-196
8. Bowe, S., Gabizon, A., Miers, I. (2017). "Scalable Multi-party Computation for zk-SNARK Parameters." https://eprint.iacr.org/2017/1050

---

## License

This project is dual-licensed under MIT and Apache-2.0. See LICENSE-MIT and LICENSE-APACHE for details.

---

Built for privacy-first digital identity on Solana.
