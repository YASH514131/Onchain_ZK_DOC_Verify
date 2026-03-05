// ──────────────────────────────────────────────────────────────────────
// setup.js – Groth16 Trusted Setup (Powers of Tau + Phase-2)
// ──────────────────────────────────────────────────────────────────────
//
// Usage: node scripts/setup.js
//
// This performs:
//   Step 1: Powers of Tau ceremony (bn128, 2^20)
//   Step 2: Phase-2 contribution
//   Step 3: Export verification key
//   Step 4: Export Solidity verifier (optional)
//
// Outputs:
//   build/pot20_final.ptau
//   build/zk_doc_auth_final.zkey
//   build/verification_key.json

const snarkjs = require("snarkjs");
const fs = require("fs");
const path = require("path");

const BUILD = path.resolve(__dirname, "..", "build");
const R1CS = path.join(BUILD, "zk_doc_auth.r1cs");
const PTAU = path.join(BUILD, "pot20_final.ptau");
const ZKEY_0 = path.join(BUILD, "zk_doc_auth_0000.zkey");
const ZKEY_FINAL = path.join(BUILD, "zk_doc_auth_final.zkey");
const VK = path.join(BUILD, "verification_key.json");

async function main() {
  console.log("╔══════════════════════════════════════════════╗");
  console.log("║   ZK-DocAuth Trusted Setup (Groth16)         ║");
  console.log("╚══════════════════════════════════════════════╝\n");

  // ── Step 1: Powers of Tau ──

  if (fs.existsSync(PTAU)) {
    console.log("[1/4] Powers of Tau file already exists, skipping.\n");
  } else {
    console.log("[1/4] Starting Powers of Tau ceremony (2^20, bn128)...");
    console.log("       This may take several minutes.\n");

    const ptau0 = path.join(BUILD, "pot20_0000.ptau");
    const ptau1 = path.join(BUILD, "pot20_0001.ptau");
    const ptauBeacon = path.join(BUILD, "pot20_beacon.ptau");

    await snarkjs.powersOfTau.newAccumulator("bn128", 20, ptau0);
    await snarkjs.powersOfTau.contribute(
      ptau0,
      ptau1,
      "ZK-DocAuth Contribution #1",
      "zk-doc-auth-entropy-seed-" + Date.now()
    );
    await snarkjs.powersOfTau.beacon(
      ptau1,
      ptauBeacon,
      "ZK-DocAuth Beacon",
      "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
      10
    );
    await snarkjs.powersOfTau.preparePhase2(ptauBeacon, PTAU);

    // Clean up intermediates.
    for (const f of [ptau0, ptau1, ptauBeacon]) {
      if (fs.existsSync(f)) fs.unlinkSync(f);
    }

    console.log("   ✅ Powers of Tau complete.\n");
  }

  // ── Step 2: Phase-2 Setup ──

  console.log("[2/4] Generating zkey (Phase-2 setup)...\n");

  if (!fs.existsSync(R1CS)) {
    console.error("   ❌ R1CS file not found. Run `npm run compile` first.");
    process.exit(1);
  }

  await snarkjs.zKey.newZKey(R1CS, PTAU, ZKEY_0);

  await snarkjs.zKey.contribute(
    ZKEY_0,
    ZKEY_FINAL,
    "ZK-DocAuth Phase-2 Contribution",
    "zk-doc-auth-phase2-" + Date.now()
  );

  // Clean up.
  if (fs.existsSync(ZKEY_0)) fs.unlinkSync(ZKEY_0);

  console.log("   ✅ zkey generated.\n");

  // ── Step 3: Export Verification Key ──

  console.log("[3/4] Exporting verification key...\n");

  const vkJson = await snarkjs.zKey.exportVerificationKey(ZKEY_FINAL);
  fs.writeFileSync(VK, JSON.stringify(vkJson, null, 2));

  console.log(`   ✅ Verification key saved to ${VK}\n`);

  // ── Step 4: Verify zkey ──

  console.log("[4/4] Verifying zkey against R1CS and PTAU...\n");

  const isValid = await snarkjs.zKey.verifyFromR1cs(R1CS, PTAU, ZKEY_FINAL);
  if (isValid) {
    console.log("   ✅ zkey verification PASSED.\n");
  } else {
    console.error("   ❌ zkey verification FAILED.");
    process.exit(1);
  }

  console.log("══════════════════════════════════════════════");
  console.log("  Setup complete. You can now generate proofs:");
  console.log("    npm run witness");
  console.log("    npm run prove");
  console.log("══════════════════════════════════════════════\n");
}

main().catch((err) => {
  console.error("Setup failed:", err);
  process.exit(1);
});
