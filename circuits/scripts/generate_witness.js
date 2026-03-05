// ──────────────────────────────────────────────────────────────────────
// generate_witness.js – Generate witness for ZK-DocAuth circuit
// ──────────────────────────────────────────────────────────────────────
//
// Usage: node scripts/generate_witness.js [input_file]
//
// Default input file: inputs/sample_input.json
//
// Output: build/witness.wtns

const snarkjs = require("snarkjs");
const fs = require("fs");
const path = require("path");

const BUILD = path.resolve(__dirname, "..", "build");
const WASM = path.join(BUILD, "zk_doc_auth_js", "zk_doc_auth.wasm");
const WITNESS = path.join(BUILD, "witness.wtns");

const defaultInput = path.resolve(__dirname, "..", "inputs", "sample_input.json");
const inputFile = process.argv[2] || defaultInput;

async function main() {
  console.log("╔══════════════════════════════════════════════╗");
  console.log("║   ZK-DocAuth Witness Generation              ║");
  console.log("╚══════════════════════════════════════════════╝\n");

  if (!fs.existsSync(WASM)) {
    console.error("❌ WASM file not found. Run `npm run compile` first.");
    process.exit(1);
  }

  if (!fs.existsSync(inputFile)) {
    console.error(`❌ Input file not found: ${inputFile}`);
    console.error("   Create an input file or use: node scripts/generate_witness.js <path>");
    process.exit(1);
  }

  console.log(`Input file: ${inputFile}`);
  const input = JSON.parse(fs.readFileSync(inputFile, "utf8"));

  console.log("\n[1/1] Generating witness...\n");

  const wc = require(path.join(BUILD, "zk_doc_auth_js", "witness_calculator.js"));
  const buffer = fs.readFileSync(WASM);
  const calculator = await wc(buffer);
  const wtns = await calculator.calculateWTNS(input);

  fs.writeFileSync(WITNESS, Buffer.from(wtns));

  console.log(`✅ Witness written to ${WITNESS}`);
  console.log(`   Witness size: ${wtns.byteLength} bytes\n`);
}

main().catch((err) => {
  console.error("Witness generation failed:", err.message || err);
  process.exit(1);
});
