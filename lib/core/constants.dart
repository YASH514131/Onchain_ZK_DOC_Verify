/// ZK-DocAuth-Solana Constants
library;

class AppConstants {
  AppConstants._();

  // ── Solana Network ──────────────────────────────────────────────────
  static const String devnetRpcUrl = 'https://api.devnet.solana.com';
  static const String mainnetRpcUrl = 'https://api.mainnet-beta.solana.com';
  static const String defaultCluster = devnetRpcUrl;

  // ── Program IDs ─────────────────────────────────────────────────────
  /// Deployed program ID on Solana devnet.
  static const String programId =
      'BXyrGdBKq9i9mpzP6AwAYy5pfSMCiEb1sZzqDySy41Qa';

  // ── PDA Seeds ───────────────────────────────────────────────────────
  static const String issuerSeed = 'issuer';
  static const String vkSeed = 'vk';
  static const String logSeed = 'log';
  static const String nullifierSeed = 'nullifier';

  // ── Merkle Tree ─────────────────────────────────────────────────────
  static const int merkleTreeDepth = 20;
  static const int maxLeaves = 1 << merkleTreeDepth; // 1,048,576

  // ── BN254 Scalar Field (Fr) ─────────────────────────────────────────
  /// p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
  static const String bn254ScalarFieldHex =
      '30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001';

  // ── Poseidon Constants ──────────────────────────────────────────────
  static const int poseidonFullRounds = 8;
  static const int poseidonPartialRounds = 57;
  static const int poseidonWidth = 3; // t = 2 inputs + 1 capacity

  // ── Proof Sizes ─────────────────────────────────────────────────────
  static const int g1PointSize = 64; // uncompressed
  static const int g2PointSize = 128; // uncompressed
  static const int groth16ProofSize = 192; // A(G1) + B(G2) + C(G1) compressed

  // ── Compute Budget ──────────────────────────────────────────────────
  static const int verificationComputeUnits = 400000;
  static const int priorityFeePerUnit = 1; // micro-lamports

  // ── Field Encoding ──────────────────────────────────────────────────
  static const int maxBytesPerFieldElement = 31;

  // ── ISO 3166-1 Numeric Country Codes (subset) ──────────────────────
  static const Map<String, int> countryCodes = {
    'India': 356,
    'USA': 840,
    'UK': 826,
    'Germany': 276,
    'France': 250,
    'Japan': 392,
    'Canada': 124,
    'Australia': 36,
    'Brazil': 76,
    'Singapore': 702,
  };
}
