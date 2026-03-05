// ZK-DocAuth Circuit: Zero Knowledge Document Authentication
//
// This circuit proves that the prover holds a valid credential whose
// Poseidon hash is a leaf in a Merkle tree with a publicly known root,
// AND the credential satisfies a specific predicate (age, nationality,
// expiry) -- all without revealing any private credential fields.
//
// Private inputs: name, dob, nationality, document_id, expiry,
//                 merkle_path[], merkle_indices[]
//
// Public inputs:  merkle_root, current_date, min_age,
//                 expected_nationality_hash
//
// Constraints:
//   1. Credential hash matches Merkle leaf (Poseidon commitment).
//   2. Merkle inclusion proof verifies against public root.
//   3. age >= min_age (range proof via bit decomposition).
//   4. hash(nationality) == expected_nationality_hash.
//   5. expiry > current_date.

pragma circom 2.1.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

// ─────────────────────────────────────────────────────────────────────
// Merkle Proof Verifier
// ─────────────────────────────────────────────────────────────────────

template MerkleProof(depth) {
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal output root;

    signal intermediates[depth + 1];
    intermediates[0] <== leaf;

    component hashers[depth];

    for (var i = 0; i < depth; i++) {
        // Constrain path index to binary.
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        hashers[i] = Poseidon(2);

        // If pathIndices[i] == 0: hash(current, sibling)
        // If pathIndices[i] == 1: hash(sibling, current)
        //
        // left  = current + index * (sibling - current)
        //       = (1-index)*current + index*sibling
        // right = sibling + index * (current - sibling)
        //       = (1-index)*sibling + index*current
        hashers[i].inputs[0] <== intermediates[i]
            + pathIndices[i] * (pathElements[i] - intermediates[i]);
        hashers[i].inputs[1] <== pathElements[i]
            + pathIndices[i] * (intermediates[i] - pathElements[i]);

        intermediates[i + 1] <== hashers[i].out;
    }

    root <== intermediates[depth];
}

// ─────────────────────────────────────────────────────────────────────
// Range Proof: a >= b
// ─────────────────────────────────────────────────────────────────────

template GreaterEqThan(n) {
    signal input in[2]; // in[0] >= in[1]
    signal output out;

    component lt = LessThan(n);
    lt.in[0] <== in[1];
    lt.in[1] <== in[0] + 1; // in[1] < in[0] + 1 <==> in[1] <= in[0]
    out <== lt.out;
}

// ─────────────────────────────────────────────────────────────────────
// Main ZK-DocAuth Circuit
// ─────────────────────────────────────────────────────────────────────

template ZKDocAuth(merkleDepth) {
    // ── Private Inputs (Witness) ──
    signal input name;
    signal input dob;               // YYYYMMDD as integer
    signal input nationality;       // ISO 3166-1 numeric
    signal input document_id;
    signal input expiry;            // YYYYMMDD as integer
    signal input merkle_path[merkleDepth];
    signal input merkle_indices[merkleDepth];

    // ── Public Inputs ──
    signal input merkle_root;
    signal input current_date;      // YYYYMMDD as integer
    signal input min_age;
    signal input expected_nationality_hash;

    // ── Output ──
    signal output valid;

    // ================================================================
    // Constraint Block 1: Credential Hash (Poseidon Commitment)
    // ================================================================

    // Hash the name.
    component name_hasher = Poseidon(1);
    name_hasher.inputs[0] <== name;

    // Hash the document ID.
    component doc_hasher = Poseidon(1);
    doc_hasher.inputs[0] <== document_id;

    // Compute credential_hash = Poseidon(name_hash, dob, nationality,
    //                                     doc_id_hash, expiry)
    component cred_hasher = Poseidon(5);
    cred_hasher.inputs[0] <== name_hasher.out;
    cred_hasher.inputs[1] <== dob;
    cred_hasher.inputs[2] <== nationality;
    cred_hasher.inputs[3] <== doc_hasher.out;
    cred_hasher.inputs[4] <== expiry;

    // ================================================================
    // Constraint Block 2: Merkle Inclusion Proof
    // ================================================================

    component merkle_verifier = MerkleProof(merkleDepth);
    merkle_verifier.leaf <== cred_hasher.out;

    for (var i = 0; i < merkleDepth; i++) {
        merkle_verifier.pathElements[i] <== merkle_path[i];
        merkle_verifier.pathIndices[i] <== merkle_indices[i];
    }

    // Enforce: computed root == public merkle_root.
    merkle_verifier.root === merkle_root;

    // ================================================================
    // Constraint Block 3: Age Verification (age >= min_age)
    // ================================================================

    // Extract year from dob (dob = YYYYMMDD, year = dob / 10000).
    signal dob_year;
    dob_year <-- dob \ 10000;

    // Constrain: dob == dob_year * 10000 + remainder
    signal dob_remainder;
    dob_remainder <== dob - dob_year * 10000;

    // Range check: 0 <= dob_remainder < 10000 (via 14-bit decomposition).
    component dob_rem_bits = Num2Bits(14);
    dob_rem_bits.in <== dob_remainder;

    // Constrain remainder < 10000.
    component dob_rem_lt = LessThan(14);
    dob_rem_lt.in[0] <== dob_remainder;
    dob_rem_lt.in[1] <== 10000;
    dob_rem_lt.out === 1;

    // Extract year from current_date.
    signal current_year;
    current_year <-- current_date \ 10000;

    signal current_remainder;
    current_remainder <== current_date - current_year * 10000;

    component cur_rem_bits = Num2Bits(14);
    cur_rem_bits.in <== current_remainder;

    component cur_rem_lt = LessThan(14);
    cur_rem_lt.in[0] <== current_remainder;
    cur_rem_lt.in[1] <== 10000;
    cur_rem_lt.out === 1;

    // Compute age = current_year - dob_year.
    signal age;
    age <== current_year - dob_year;

    // Enforce: age >= min_age.
    component age_check = GreaterEqThan(8);
    age_check.in[0] <== age;
    age_check.in[1] <== min_age;
    age_check.out === 1;

    // ================================================================
    // Constraint Block 4: Nationality Verification
    // ================================================================

    component nat_hasher = Poseidon(1);
    nat_hasher.inputs[0] <== nationality;

    // Enforce: Poseidon(nationality) == expected_nationality_hash.
    nat_hasher.out === expected_nationality_hash;

    // ================================================================
    // Constraint Block 5: Document Expiry Check
    // ================================================================

    // Enforce: expiry > current_date.
    // Equivalently: expiry - current_date - 1 >= 0 (via 32-bit range proof).
    component expiry_check = GreaterEqThan(32);
    expiry_check.in[0] <== expiry;
    expiry_check.in[1] <== current_date + 1;
    expiry_check.out === 1;

    // ================================================================
    // Output
    // ================================================================

    // If all constraints pass, valid = 1.
    valid <== 1;
}

// ── Main Component ──────────────────────────────────────────────────
//
// Public inputs: merkle_root, current_date, min_age,
//                expected_nationality_hash
//
// Merkle tree depth: 20 (supports 2^20 = 1,048,576 credentials).

component main {public [
    merkle_root,
    current_date,
    min_age,
    expected_nationality_hash
]} = ZKDocAuth(20);
