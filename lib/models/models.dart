/// Data models for ZK-DocAuth credentials and proofs.
library;

import 'dart:typed_data';

import '../core/utils.dart';

// ─────────────────────────────────────────────────────────────────────────────
// Credential
// ─────────────────────────────────────────────────────────────────────────────

/// Represents a verified KYC credential issued by a trusted authority.
class Credential {
  Credential({
    required this.name,
    required this.dob,
    required this.nationality,
    required this.nationalityCode,
    required this.documentId,
    required this.expiry,
    required this.issuedAt,
    required this.issuerPublicKey,
    this.leafIndex,
  });

  /// Full legal name as on document.
  final String name;

  /// Date of birth in YYYYMMDD format.
  final int dob;

  /// Country name (human-readable).
  final String nationality;

  /// ISO 3166-1 numeric country code.
  final int nationalityCode;

  /// Document identifier (passport number, national ID, etc.).
  final String documentId;

  /// Document expiry date in YYYYMMDD format.
  final int expiry;

  /// Unix timestamp of issuance.
  final int issuedAt;

  /// Base58 public key of the issuing authority.
  final String issuerPublicKey;

  /// Index of the credential's leaf in the Merkle tree; assigned after insertion.
  int? leafIndex;

  /// Field-encoded representation for circuit input.
  Map<String, BigInt> toFieldElements() {
    return {
      'name': fieldEncodeString(name),
      'dob': fieldEncodeDate(dob),
      'nationality': fieldEncodeCountry(nationalityCode),
      'document_id': fieldEncodeString(documentId),
      'expiry': fieldEncodeDate(expiry),
    };
  }

  Map<String, dynamic> toJson() => {
    'name': name,
    'dob': dob,
    'nationality': nationality,
    'nationalityCode': nationalityCode,
    'documentId': documentId,
    'expiry': expiry,
    'issuedAt': issuedAt,
    'issuerPublicKey': issuerPublicKey,
    'leafIndex': leafIndex,
  };

  factory Credential.fromJson(Map<String, dynamic> json) => Credential(
    name: json['name'] as String,
    dob: json['dob'] as int,
    nationality: json['nationality'] as String,
    nationalityCode: json['nationalityCode'] as int,
    documentId: json['documentId'] as String,
    expiry: json['expiry'] as int,
    issuedAt: json['issuedAt'] as int,
    issuerPublicKey: json['issuerPublicKey'] as String,
    leafIndex: json['leafIndex'] as int?,
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Merkle Proof Data
// ─────────────────────────────────────────────────────────────────────────────

/// Merkle inclusion proof: path elements + direction indices.
class MerkleProofData {
  const MerkleProofData({
    required this.pathElements,
    required this.pathIndices,
    required this.leaf,
    required this.root,
  });

  /// Sibling hashes along the path from leaf to root.
  final List<BigInt> pathElements;

  /// Binary direction indicators (0 = left, 1 = right) at each level.
  final List<int> pathIndices;

  /// The leaf value (credential hash).
  final BigInt leaf;

  /// The Merkle root.
  final BigInt root;
}

// ─────────────────────────────────────────────────────────────────────────────
// Groth16 Proof
// ─────────────────────────────────────────────────────────────────────────────

/// A Groth16 proof consisting of three curve points.
class Groth16Proof {
  const Groth16Proof({required this.a, required this.b, required this.c});

  /// G1 point A (64 bytes uncompressed).
  final G1Point a;

  /// G2 point B (128 bytes uncompressed).
  final G2Point b;

  /// G1 point C (64 bytes uncompressed).
  final G1Point c;

  /// Serialize to bytes for on-chain submission (256 bytes).
  Uint8List serialize() {
    final buffer = BytesBuilder();
    buffer.add(a.serialize());
    buffer.add(b.serialize());
    buffer.add(c.serialize());
    return buffer.toBytes();
  }

  Map<String, dynamic> toJson() => {
    'a': a.toJson(),
    'b': b.toJson(),
    'c': c.toJson(),
  };

  factory Groth16Proof.fromJson(Map<String, dynamic> json) => Groth16Proof(
    a: G1Point.fromJson(json['a'] as Map<String, dynamic>),
    b: G2Point.fromJson(json['b'] as Map<String, dynamic>),
    c: G1Point.fromJson(json['c'] as Map<String, dynamic>),
  );
}

/// A point on the G1 curve (BN254).
class G1Point {
  const G1Point({required this.x, required this.y});

  final BigInt x;
  final BigInt y;

  Uint8List serialize() {
    final buffer = BytesBuilder();
    buffer.add(bigIntToBytes32(x));
    buffer.add(bigIntToBytes32(y));
    return buffer.toBytes();
  }

  Map<String, String> toJson() => {
    'x': '0x${x.toRadixString(16)}',
    'y': '0x${y.toRadixString(16)}',
  };

  factory G1Point.fromJson(Map<String, dynamic> json) => G1Point(
    x: BigInt.parse((json['x'] as String).replaceFirst('0x', ''), radix: 16),
    y: BigInt.parse((json['y'] as String).replaceFirst('0x', ''), radix: 16),
  );
}

/// A point on the G2 curve (BN254) over Fp2.
class G2Point {
  const G2Point({
    required this.xC0,
    required this.xC1,
    required this.yC0,
    required this.yC1,
  });

  final BigInt xC0;
  final BigInt xC1;
  final BigInt yC0;
  final BigInt yC1;

  Uint8List serialize() {
    final buffer = BytesBuilder();
    buffer.add(bigIntToBytes32(xC0));
    buffer.add(bigIntToBytes32(xC1));
    buffer.add(bigIntToBytes32(yC0));
    buffer.add(bigIntToBytes32(yC1));
    return buffer.toBytes();
  }

  Map<String, String> toJson() => {
    'xC0': '0x${xC0.toRadixString(16)}',
    'xC1': '0x${xC1.toRadixString(16)}',
    'yC0': '0x${yC0.toRadixString(16)}',
    'yC1': '0x${yC1.toRadixString(16)}',
  };

  factory G2Point.fromJson(Map<String, dynamic> json) => G2Point(
    xC0: BigInt.parse(
      (json['xC0'] as String).replaceFirst('0x', ''),
      radix: 16,
    ),
    xC1: BigInt.parse(
      (json['xC1'] as String).replaceFirst('0x', ''),
      radix: 16,
    ),
    yC0: BigInt.parse(
      (json['yC0'] as String).replaceFirst('0x', ''),
      radix: 16,
    ),
    yC1: BigInt.parse(
      (json['yC1'] as String).replaceFirst('0x', ''),
      radix: 16,
    ),
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Public Inputs
// ─────────────────────────────────────────────────────────────────────────────

/// Public inputs submitted alongside the proof for on-chain verification.
class ProofPublicInputs {
  const ProofPublicInputs({
    required this.merkleRoot,
    required this.currentDate,
    required this.minAge,
    required this.expectedNationalityHash,
  });

  final BigInt merkleRoot;
  final int currentDate;
  final int minAge;
  final BigInt expectedNationalityHash;

  /// Serialize public inputs as a Borsh-encoded Vec<[u8; 32]>.
  ///
  /// Borsh Vec = 4-byte LE length prefix + N * 32-byte elements.
  Uint8List serialize() {
    final elements = toFieldElements();
    final buffer = BytesBuilder();
    // 4-byte LE length prefix (Borsh Vec encoding)
    final lenBytes = ByteData(4);
    lenBytes.setUint32(0, elements.length, Endian.little);
    buffer.add(lenBytes.buffer.asUint8List());
    for (final el in elements) {
      buffer.add(bigIntToBytes32(el));
    }
    return buffer.toBytes();
  }

  List<BigInt> toFieldElements() => [
    merkleRoot,
    BigInt.from(currentDate),
    BigInt.from(minAge),
    expectedNationalityHash,
  ];
}

// ─────────────────────────────────────────────────────────────────────────────
// Verification Result
// ─────────────────────────────────────────────────────────────────────────────

/// Nullifier hash to prevent double-use of a proof.
Uint8List serializeNullifierHash(BigInt nullifierHash) {
  return bigIntToBytes32(nullifierHash);
}

/// Result of an on-chain or local proof verification.
class VerificationResult {
  const VerificationResult({
    required this.isValid,
    required this.timestamp,
    this.transactionSignature,
    this.errorMessage,
  });

  final bool isValid;
  final DateTime timestamp;
  final String? transactionSignature;
  final String? errorMessage;
}

// ─────────────────────────────────────────────────────────────────────────────
// Issuer Info
// ─────────────────────────────────────────────────────────────────────────────

/// On-chain issuer account state mirrored in the client.
class IssuerInfo {
  const IssuerInfo({
    required this.authority,
    required this.merkleRoot,
    required this.revocationRoot,
    required this.treeSize,
    required this.lastUpdated,
    required this.name,
    required this.isActive,
  });

  final String authority;
  final Uint8List merkleRoot;
  final Uint8List revocationRoot;
  final int treeSize;
  final int lastUpdated;
  final String name;
  final bool isActive;
}
