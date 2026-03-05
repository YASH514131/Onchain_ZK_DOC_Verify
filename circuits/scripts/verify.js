// ──────────────────────────────────────────────────────────────────────
// verify.js – Verify a Groth16 proof off-chain
// ──────────────────────────────────────────────────────────────────────
//
// Usage: node scripts/verify.js
//
// Inputs:
//   build/verification_key.json
//   build/proof.json
//   build/public.json

const snarkjs = require("snarkjs");
const fs = require("fs");
const path = require("path");

const BUILD = path.resolve(__dirname, "..", "build");
const VK = path.join(BUILD, "verification_key.json");
const PROOF = path.join(BUILD, "proof.json");
const PUBLIC = path.join(BUILD, "public.json");

async function main() {
  console.log("╔══════════════════════════════════════════════╗");
  console.log("║   ZK-DocAuth Proof Verification              ║");
  console.log("╚══════════════════════════════════════════════╝\n");

  for (const [label, fp] of [
    ["Verification key", VK],
    ["Proof", PROOF],
    ["Public signals", PUBLIC],
  ]) {
    if (!fs.existsSync(fp)) {
      console.error(`❌ ${label} not found: ${fp}`);
      process.exit(1);
    }
  }

  const vk = JSON.parse(fs.readFileSync(VK, "utf8"));
  const proof = JSON.parse(fs.readFileSync(PROOF, "utf8"));
  const publicSignals = JSON.parse(fs.readFileSync(PUBLIC, "utf8"));

  console.log("[1/1] Verifying proof...\n");

  const startTime = Date.now();
  const isValid = await snarkjs.groth16.verify(vk, publicSignals, proof);
  const elapsed = Date.now() - startTime;

  if (isValid) {
    console.log(`✅ Proof is VALID (verified in ${elapsed}ms)`);
  } else {
    console.log(`❌ Proof is INVALID (checked in ${elapsed}ms)`);
    process.exit(1);
  }

  console.log("\n── Public Signals ─────────────────────────────");
  const labels = ["merkle_root", "current_date", "min_age", "expected_nationality_hash", "valid"];
  publicSignals.forEach((sig, i) => {
    const label = labels[i] || `signal_${i}`;
    console.log(`   ${label}: ${sig}`);
  });
  console.log("");
}

main().catch((err) => {
  console.error("Verification failed:", err.message || err);
  process.exit(1);
});
