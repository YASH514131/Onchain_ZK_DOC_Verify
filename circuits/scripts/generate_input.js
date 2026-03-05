// ──────────────────────────────────────────────────────────────────────
// generate_input.js – Generate circuit input JSON from credential data
// ──────────────────────────────────────────────────────────────────────
//
// This script takes human-readable credential fields, computes the
// Poseidon hashes, builds a Merkle tree, and outputs a complete
// input.json file ready for witness generation.
//
// Usage:
//   node scripts/generate_input.js
//   node scripts/generate_input.js --output inputs/my_input.json
//
// You can modify the CREDENTIAL and CLAIM constants below.

const { buildPoseidon } = require("circomlibjs") || (() => {
  console.log("Note: circomlibjs not installed. Using placeholder values.");
  return null;
})();
const fs = require("fs");
const path = require("path");

// ── Credential Data ──────────────────────────────────────────────────

const CREDENTIAL = {
  name: "John Doe",
  dob: 19950115,      // January 15, 1995
  nationality: 840,   // USA (ISO 3166-1 numeric)
  document_id: "AB12345678",
  expiry: 20280630,   // June 30, 2028
};

const CLAIM = {
  current_date: 20250115,
  min_age: 18,
};

const MERKLE_DEPTH = 20;

// ── Helpers ──────────────────────────────────────────────────────────

function stringToFieldElement(str) {
  // Convert string to a field element by hashing its UTF-8 bytes.
  // In production, this should match the Dart-side encoding exactly.
  let result = BigInt(0);
  for (let i = 0; i < str.length && i < 31; i++) {
    result = result + BigInt(str.charCodeAt(i)) * BigInt(256) ** BigInt(i);
  }
  return result;
}

async function main() {
  let poseidon;
  let F;

  try {
    const buildPoseidon = require("circomlibjs").buildPoseidon;
    poseidon = await buildPoseidon();
    F = poseidon.F;
  } catch {
    console.log("⚠️  circomlibjs not available. Generating placeholder input.\n");
    console.log("   Install it: npm install circomlibjs\n");

    // Generate a placeholder input for structure reference.
    const placeholder = {
      // Private inputs
      name: stringToFieldElement(CREDENTIAL.name).toString(),
      dob: CREDENTIAL.dob.toString(),
      nationality: CREDENTIAL.nationality.toString(),
      document_id: stringToFieldElement(CREDENTIAL.document_id).toString(),
      expiry: CREDENTIAL.expiry.toString(),
      merkle_path: Array(MERKLE_DEPTH).fill("0"),
      merkle_indices: Array(MERKLE_DEPTH).fill("0"),
      // Public inputs
      merkle_root: "0",
      current_date: CLAIM.current_date.toString(),
      min_age: CLAIM.min_age.toString(),
      expected_nationality_hash: "0",
    };

    const outFile = getOutputPath();
    fs.mkdirSync(path.dirname(outFile), { recursive: true });
    fs.writeFileSync(outFile, JSON.stringify(placeholder, null, 2));
    console.log(`📄 Placeholder input written to ${outFile}`);
    return;
  }

  // ── Compute Poseidon hashes ──

  const nameField = stringToFieldElement(CREDENTIAL.name);
  const docIdField = stringToFieldElement(CREDENTIAL.document_id);

  const nameHash = poseidon([nameField]);
  const docHash = poseidon([docIdField]);

  // Credential commitment = Poseidon(nameHash, dob, nationality, docHash, expiry)
  const credHash = poseidon([
    F.toObject(nameHash),
    BigInt(CREDENTIAL.dob),
    BigInt(CREDENTIAL.nationality),
    F.toObject(docHash),
    BigInt(CREDENTIAL.expiry),
  ]);

  const credHashValue = F.toObject(credHash);

  // Nationality hash for public input.
  const natHash = poseidon([BigInt(CREDENTIAL.nationality)]);
  const natHashValue = F.toObject(natHash);

  // ── Build minimal Merkle tree ──

  // Zero value for empty leaves.
  const ZERO = BigInt(0);

  // Compute zero hashes for each level.
  const zeroHashes = [ZERO];
  for (let i = 1; i <= MERKLE_DEPTH; i++) {
    const h = poseidon([zeroHashes[i - 1], zeroHashes[i - 1]]);
    zeroHashes.push(F.toObject(h));
  }

  // Insert credential as leaf at index 0.
  let currentHash = credHashValue;
  const merklePath = [];
  const merkleIndices = [];

  for (let i = 0; i < MERKLE_DEPTH; i++) {
    merklePath.push(zeroHashes[i].toString());
    merkleIndices.push("0"); // Leaf is always on the left.

    // hash(currentHash, zeroHashes[i])
    const h = poseidon([currentHash, zeroHashes[i]]);
    currentHash = F.toObject(h);
  }

  const merkleRoot = currentHash;

  // ── Assemble input ──

  const input = {
    // Private inputs
    name: nameField.toString(),
    dob: CREDENTIAL.dob.toString(),
    nationality: CREDENTIAL.nationality.toString(),
    document_id: docIdField.toString(),
    expiry: CREDENTIAL.expiry.toString(),
    merkle_path: merklePath,
    merkle_indices: merkleIndices,

    // Public inputs
    merkle_root: merkleRoot.toString(),
    current_date: CLAIM.current_date.toString(),
    min_age: CLAIM.min_age.toString(),
    expected_nationality_hash: natHashValue.toString(),
  };

  const outFile = getOutputPath();
  fs.mkdirSync(path.dirname(outFile), { recursive: true });
  fs.writeFileSync(outFile, JSON.stringify(input, null, 2));

  console.log("╔══════════════════════════════════════════════╗");
  console.log("║   ZK-DocAuth Input Generated                 ║");
  console.log("╚══════════════════════════════════════════════╝\n");
  console.log(`📄 Input written to ${outFile}\n`);
  console.log("── Credential ─────────────────────────────────");
  console.log(`   Name:         ${CREDENTIAL.name}`);
  console.log(`   DOB:          ${CREDENTIAL.dob}`);
  console.log(`   Nationality:  ${CREDENTIAL.nationality} (USA)`);
  console.log(`   Document ID:  ${CREDENTIAL.document_id}`);
  console.log(`   Expiry:       ${CREDENTIAL.expiry}`);
  console.log("");
  console.log("── Computed Values ────────────────────────────");
  console.log(`   Cred Hash:    ${credHashValue.toString().substring(0, 40)}...`);
  console.log(`   Merkle Root:  ${merkleRoot.toString().substring(0, 40)}...`);
  console.log(`   Nat Hash:     ${natHashValue.toString().substring(0, 40)}...`);
  console.log("");
  console.log("── Claim ──────────────────────────────────────");
  console.log(`   Current Date: ${CLAIM.current_date}`);
  console.log(`   Min Age:      ${CLAIM.min_age}`);
  console.log("");
}

function getOutputPath() {
  const idx = process.argv.indexOf("--output");
  if (idx !== -1 && process.argv[idx + 1]) {
    return path.resolve(process.argv[idx + 1]);
  }
  return path.resolve(__dirname, "..", "inputs", "sample_input.json");
}

main().catch((err) => {
  console.error("Input generation failed:", err);
  process.exit(1);
});
