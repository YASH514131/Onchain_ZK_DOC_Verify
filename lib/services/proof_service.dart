/// Zero-Knowledge proof generation and local verification service.
///
/// In a production build this would invoke a WASM-compiled Circom prover
/// (via snarkjs) through platform channels or an FFI bridge.
///
/// This implementation provides:
/// 1. Witness construction from credential + Merkle proof + claim.
/// 2. A simulated proof generation path that validates constraint
///    satisfaction locally (for development/testing).
/// 3. Serialization of proof + public inputs for on-chain submission.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import '../core/exceptions.dart';
import '../core/utils.dart';
import '../crypto/merkle_tree.dart';
import '../crypto/poseidon.dart';
import '../models/models.dart';
import 'credential_service.dart';

/// The type of claim the user wants to prove.
enum ClaimType {
  ageAbove,
  nationalityEquals,
  documentNotExpired,
  credentialValid,
  nameHashEquals,
}

/// Input bundle for proof generation.
class ProofRequest {
  const ProofRequest({
    required this.credential,
    required this.merkleProof,
    required this.claimType,
    this.minAge,
    this.expectedNationalityCode,
    this.expectedNameHash,
    this.currentDate,
  });

  final Credential credential;
  final MerkleProofData merkleProof;
  final ClaimType claimType;
  final int? minAge;
  final int? expectedNationalityCode;
  final BigInt? expectedNameHash;

  /// Override for testing; defaults to today.
  final int? currentDate;
}

/// Output of proof generation.
class ProofOutput {
  const ProofOutput({
    required this.proof,
    required this.publicInputs,
    required this.nullifierHash,
    required this.witnessValid,
  });

  final Groth16Proof proof;
  final ProofPublicInputs publicInputs;

  /// Deterministic nullifier hash derived from the credential commitment
  /// and Merkle leaf index, preventing double-use of a proof.
  final BigInt nullifierHash;

  /// Whether local witness validation succeeded (always true for a valid proof).
  final bool witnessValid;
}

class ZKProofService {
  ZKProofService({CredentialService? credentialService})
    : _credentialService = credentialService ?? CredentialService();

  final CredentialService _credentialService;

  // ── Proof Generation ───────────────────────────────────────────────

  /// Generate a zero-knowledge proof for the given [request].
  ///
  /// This method:
  /// 1. Validates constraint satisfaction locally.
  /// 2. Constructs witness and public inputs.
  /// 3. Invokes the Groth16 prover (simulated in dev builds).
  Future<ProofOutput> generateProof(ProofRequest request) async {
    // ── Step 1: Build witness ──
    final witness = _buildWitness(request);

    // ── Step 2: Validate constraints locally ──
    final constraintsSatisfied = _validateConstraints(witness, request);
    if (!constraintsSatisfied) {
      throw const ProofGenerationException(
        'Constraint validation failed: the claim cannot be proven with this credential',
      );
    }

    // ── Step 3: Construct public inputs ──
    final currentDate = request.currentDate ?? todayAsYYYYMMDD();
    final nationalityHash = _credentialService.computeNationalityHash(
      request.expectedNationalityCode ?? request.credential.nationalityCode,
    );

    final publicInputs = ProofPublicInputs(
      merkleRoot: request.merkleProof.root,
      currentDate: currentDate,
      minAge: request.minAge ?? 0,
      expectedNationalityHash: nationalityHash,
    );

    // ── Step 4: Compute nullifier hash ──
    // Nullifier = Poseidon(commitment, leafIndex) to prevent double-use.
    final commitment = _credentialService.computeCommitment(request.credential);
    final leafIndex = request.credential.leafIndex ?? 0;
    final nullifierHash = PoseidonHash.hash2(
      commitment,
      BigInt.from(leafIndex),
    );

    // ── Step 5: Generate Groth16 proof ──
    // TODO(production): Replace with actual WASM prover invocation via
    // platform channel:
    //   final proofJson = await _platformChannel.invokeMethod('generateProof', {
    //     'witness': witness,
    //     'wasmPath': 'assets/circuits/zk_doc_auth.wasm',
    //     'zkeyPath': 'assets/circuits/circuit_final.zkey',
    //   });
    final proof = _simulateProofGeneration(witness, publicInputs);

    return ProofOutput(
      proof: proof,
      publicInputs: publicInputs,
      nullifierHash: nullifierHash,
      witnessValid: constraintsSatisfied,
    );
  }

  // ── Witness Construction ───────────────────────────────────────────

  Map<String, dynamic> _buildWitness(ProofRequest request) {
    final cred = request.credential;
    final fields = cred.toFieldElements();

    return {
      // Private inputs
      'name': fields['name']!.toString(),
      'dob': fields['dob']!.toString(),
      'nationality': fields['nationality']!.toString(),
      'document_id': fields['document_id']!.toString(),
      'expiry': fields['expiry']!.toString(),
      'merkle_path': request.merkleProof.pathElements
          .map((e) => e.toString())
          .toList(),
      'merkle_indices': request.merkleProof.pathIndices,

      // Public inputs
      'merkle_root': request.merkleProof.root.toString(),
      'current_date': (request.currentDate ?? todayAsYYYYMMDD()).toString(),
      'min_age': (request.minAge ?? 0).toString(),
      'expected_nationality_hash': _credentialService
          .computeNationalityHash(
            request.expectedNationalityCode ??
                request.credential.nationalityCode,
          )
          .toString(),
    };
  }

  // ── Local Constraint Validation ────────────────────────────────────

  bool _validateConstraints(
    Map<String, dynamic> witness,
    ProofRequest request,
  ) {
    try {
      final cred = request.credential;
      final currentDate = request.currentDate ?? todayAsYYYYMMDD();

      // Constraint 1: Credential hash matches Merkle leaf.
      final commitment = _credentialService.computeCommitment(cred);
      if (commitment != request.merkleProof.leaf) {
        return false;
      }

      // Constraint 2: Merkle inclusion.
      final validInclusion = MerkleTree.verifyProofAgainstRoot(
        request.merkleProof.leaf,
        request.merkleProof.pathElements,
        request.merkleProof.pathIndices,
        request.merkleProof.root,
      );
      if (!validInclusion) return false;

      // Constraint 3: Claim-specific checks.
      switch (request.claimType) {
        case ClaimType.ageAbove:
          final age = computeAge(cred.dob, referenceDate: currentDate);
          if (age < (request.minAge ?? 18)) return false;
          break;

        case ClaimType.nationalityEquals:
          final expectedCode = request.expectedNationalityCode;
          if (expectedCode == null || cred.nationalityCode != expectedCode) {
            return false;
          }
          break;

        case ClaimType.documentNotExpired:
          if (cred.expiry <= currentDate) return false;
          break;

        case ClaimType.credentialValid:
          // Merkle inclusion is sufficient for basic validity.
          break;

        case ClaimType.nameHashEquals:
          if (request.expectedNameHash == null) return false;
          final nameHash = PoseidonHash.hash1(fieldEncodeString(cred.name));
          if (nameHash != request.expectedNameHash) return false;
          break;
      }

      // Constraint 4: Document not expired (always checked).
      if (cred.expiry <= currentDate) return false;

      return true;
    } catch (_) {
      return false;
    }
  }

  // ── Simulated Prover ───────────────────────────────────────────────
  //
  // In production, this is replaced by the snarkjs WASM prover.
  // The simulated proof uses deterministic dummy values derived from
  // the witness hash so that the proof structure is valid but will
  // only pass the on-chain verifier with a matching simulated verifier.

  Groth16Proof _simulateProofGeneration(
    Map<String, dynamic> witness,
    ProofPublicInputs publicInputs,
  ) {
    // Deterministic "proof" derived from credential commitment.
    final seed = PoseidonHash.hash2(
      publicInputs.merkleRoot,
      BigInt.from(publicInputs.currentDate),
    );

    // Simulated curve points (NOT cryptographically valid on BN254).
    return Groth16Proof(
      a: G1Point(x: seed, y: fieldReduce(seed + BigInt.one)),
      b: G2Point(
        xC0: fieldReduce(seed + BigInt.two),
        xC1: fieldReduce(seed + BigInt.from(3)),
        yC0: fieldReduce(seed + BigInt.from(4)),
        yC1: fieldReduce(seed + BigInt.from(5)),
      ),
      c: G1Point(
        x: fieldReduce(seed + BigInt.from(6)),
        y: fieldReduce(seed + BigInt.from(7)),
      ),
    );
  }

  // ── Public Utilities ───────────────────────────────────────────────

  /// Serialize a proof + public inputs + nullifierHash for Solana instruction data.
  Uint8List serializeForSolana(ProofOutput output) {
    final buffer = BytesBuilder();

    // Anchor discriminator: SHA256("global:verify_proof")[0..8]
    final disc = sha256.convert(utf8.encode('global:verify_proof'));
    buffer.add(Uint8List.fromList(disc.bytes.sublist(0, 8)));

    // proofA [u8; 64]
    buffer.add(output.proof.a.serialize());

    // proofB [u8; 128]
    buffer.add(output.proof.b.serialize());

    // proofC [u8; 64]
    buffer.add(output.proof.c.serialize());

    // publicInputs Vec<[u8; 32]> (Borsh Vec with length prefix)
    buffer.add(output.publicInputs.serialize());

    // nullifierHash [u8; 32]
    buffer.add(bigIntToBytes32(output.nullifierHash));

    return buffer.toBytes();
  }
}
