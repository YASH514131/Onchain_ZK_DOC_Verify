// ──────────────────────────────────────────────────────────────────────
// prove.js – Generate Groth16 proof for ZK-DocAuth
// ──────────────────────────────────────────────────────────────────────
//
// Usage: node scripts/prove.js
//
// Inputs:
//   build/zk_doc_auth_final.zkey
//   build/witness.wtns
//
// Outputs:
//   build/proof.json
//   build/public.json

const snarkjs = require("snarkjs");
const fs = require("fs");
const path = require("path");

const BUILD = path.resolve(__dirname, "..", "build");
const ZKEY = path.join(BUILD, "zk_doc_auth_final.zkey");
const WITNESS = path.join(BUILD, "witness.wtns");
const PROOF_OUT = path.join(BUILD, "proof.json");
const PUBLIC_OUT = path.join(BUILD, "public.json");

async function main() {
  console.log("╔══════════════════════════════════════════════╗");
  console.log("║   ZK-DocAuth Groth16 Proof Generation        ║");
  console.log("╚══════════════════════════════════════════════╝\n");

  if (!fs.existsSync(ZKEY)) {
    console.error("❌ zkey not found. Run `npm run setup` first.");
    process.exit(1);
  }

  if (!fs.existsSync(WITNESS)) {
    console.error("❌ Witness not found. Run `npm run witness` first.");
    process.exit(1);
  }

  console.log("[1/1] Generating Groth16 proof...\n");

  const startTime = Date.now();

  const { proof, publicSignals } = await snarkjs.groth16.prove(ZKEY, WITNESS);

  const elapsed = Date.now() - startTime;

  fs.writeFileSync(PROOF_OUT, JSON.stringify(proof, null, 2));
  fs.writeFileSync(PUBLIC_OUT, JSON.stringify(publicSignals, null, 2));

  console.log(`✅ Proof generated in ${elapsed}ms`);
  console.log(`   Proof:   ${PROOF_OUT}`);
  console.log(`   Public:  ${PUBLIC_OUT}`);
  console.log("\n── Proof ──────────────────────────────────────");
  console.log(`   pi_a: [${proof.pi_a[0].substring(0, 20)}..., ${proof.pi_a[1].substring(0, 20)}...]`);
  console.log(`   pi_b: [[${proof.pi_b[0][0].substring(0, 16)}..., ...], ...]`);
  console.log(`   pi_c: [${proof.pi_c[0].substring(0, 20)}..., ${proof.pi_c[1].substring(0, 20)}...]`);
  console.log("\n── Public Signals ─────────────────────────────");
  publicSignals.forEach((sig, i) => {
    console.log(`   [${i}]: ${sig}`);
  });
  console.log("");
}

main().catch((err) => {
  console.error("Proof generation failed:", err.message || err);
  process.exit(1);
});
