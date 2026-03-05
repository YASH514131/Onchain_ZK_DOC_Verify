// ──────────────────────────────────────────────────────────────────────
// compile.js – Compile the ZK-DocAuth Circom circuit
// ──────────────────────────────────────────────────────────────────────
//
// Usage: node scripts/compile.js
//
// Prerequisites:
//   - circom 2.1.x installed (https://docs.circom.io/getting-started/installation/)
//   - npm install (to pull circomlib)
//
// Outputs:
//   build/zk_doc_auth.r1cs
//   build/zk_doc_auth.wasm
//   build/zk_doc_auth.sym

const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const BUILD_DIR = path.join(ROOT, "build");
const CIRCUIT = path.join(ROOT, "src", "zk_doc_auth.circom");

// Create build directory.
if (!fs.existsSync(BUILD_DIR)) {
  fs.mkdirSync(BUILD_DIR, { recursive: true });
}

console.log("╔══════════════════════════════════════════════╗");
console.log("║   ZK-DocAuth Circuit Compilation             ║");
console.log("╚══════════════════════════════════════════════╝\n");

console.log(`[1/1] Compiling ${path.basename(CIRCUIT)} ...\n`);

const cmd = [
  "circom",
  `"${CIRCUIT}"`,
  "--r1cs",
  "--wasm",
  "--sym",
  "--prime bn128",
  `-o "${BUILD_DIR}"`,
].join(" ");

try {
  execSync(cmd, { stdio: "inherit", cwd: ROOT });
  console.log("\n✅ Compilation successful.");
  console.log(`   R1CS:  ${path.join(BUILD_DIR, "zk_doc_auth.r1cs")}`);
  console.log(`   WASM:  ${path.join(BUILD_DIR, "zk_doc_auth_js", "zk_doc_auth.wasm")}`);
  console.log(`   SYM:   ${path.join(BUILD_DIR, "zk_doc_auth.sym")}`);
} catch (err) {
  console.error("\n❌ Compilation failed. Make sure circom 2.1+ is installed.");
  process.exit(1);
}
