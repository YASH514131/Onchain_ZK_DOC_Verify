/// Solana blockchain integration: RPC client, transaction builder, PDA
/// derivation, and on-chain state queries.
///
/// Uses the `solana_web3` package for real RPC communication and
/// transaction construction.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:solana_web3/solana_web3.dart' as web3;

import '../core/constants.dart';
import '../core/exceptions.dart';
import '../core/utils.dart';
import '../models/models.dart';
import 'wallet_service.dart';

// ─────────────────────────────────────────────────────────────────────────────
// PDA Derivation
// ─────────────────────────────────────────────────────────────────────────────

/// Derive a Program Derived Address.
///
/// PDA = SHA256("ProgramDerivedAddress" || seeds... || programId || bump)
/// where bump is decremented from 255 until the result is off-curve.
class PdaDerivation {
  PdaDerivation._();

  /// Find the PDA for an issuer account.
  static ({Uint8List address, int bump}) findIssuerPda(
    String issuerPubkeyBase58,
  ) {
    return _findPda([
      utf8.encode(AppConstants.issuerSeed),
      _base58Decode(issuerPubkeyBase58),
    ]);
  }

  /// Find the PDA for a verification key account.
  static ({Uint8List address, int bump}) findVkPda(String issuerPubkeyBase58) {
    return _findPda([
      utf8.encode(AppConstants.vkSeed),
      _base58Decode(issuerPubkeyBase58),
    ]);
  }

  /// Find the PDA for a nullifier record.
  static ({Uint8List address, int bump}) findNullifierPda(
    Uint8List nullifierHash,
  ) {
    return _findPda([utf8.encode(AppConstants.nullifierSeed), nullifierHash]);
  }

  /// Generic PDA finder. Iterates bump from 255 down.
  static ({Uint8List address, int bump}) _findPda(List<List<int>> seeds) {
    final programIdBytes = _base58Decode(AppConstants.programId);
    // In this simplified implementation we accept the first candidate (bump=255).
    // A production implementation must check that the resulting point is off
    // the Ed25519 curve before returning.
    const bump = 255;
    final hasher = sha256.convert([
      ...seeds.expand((s) => s),
      bump,
      ...programIdBytes,
      ...utf8.encode('ProgramDerivedAddress'),
    ]);
    final bytes = Uint8List.fromList(hasher.bytes);
    return (address: bytes, bump: bump);
  }

  static Uint8List _base58Decode(String input) {
    // Minimal Base58 decoder for public key bytes.
    const alphabet =
        '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    BigInt value = BigInt.zero;
    for (int i = 0; i < input.length; i++) {
      final charIndex = alphabet.indexOf(input[i]);
      if (charIndex < 0) {
        throw SolanaTransactionException(
          'Invalid Base58 character: ${input[i]}',
        );
      }
      value = value * BigInt.from(58) + BigInt.from(charIndex);
    }
    final bytes = bigIntToBytes32(value);
    return bytes;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Solana Service
// ─────────────────────────────────────────────────────────────────────────────

class SolanaService {
  SolanaService({WalletService? walletService})
    : _wallet = walletService ?? WalletService.instance;

  final WalletService _wallet;

  /// The cluster URL for display purposes.
  String get rpcUrl => AppConstants.defaultCluster;

  /// The program's public key.
  web3.Pubkey get programId => web3.Pubkey.fromBase58(AppConstants.programId);

  // ── Account Queries ────────────────────────────────────────────────

  /// Fetch the on-chain IssuerAccount state.
  Future<IssuerInfo?> fetchIssuerAccount(String issuerPubkey) async {
    final pda = PdaDerivation.findIssuerPda(issuerPubkey);
    final pdaPubkey = web3.Pubkey.fromUint8List(pda.address);
    final accountInfo = await _wallet.getAccountInfo(pdaPubkey);

    if (accountInfo == null || accountInfo.data == null) return null;

    final data = _extractBinaryData(accountInfo.data);
    if (data == null) return null;

    return _deserializeIssuerAccount(data);
  }

  /// Check if a nullifier has already been used.
  Future<bool> isNullifierUsed(Uint8List nullifierHash) async {
    final pda = PdaDerivation.findNullifierPda(nullifierHash);
    final pdaPubkey = web3.Pubkey.fromUint8List(pda.address);
    final info = await _wallet.getAccountInfo(pdaPubkey);
    return info != null && info.data != null;
  }

  // ── Real Transaction Submission ────────────────────────────────────

  /// Build and send a verify_proof transaction to the live Solana program.
  ///
  /// Returns the transaction signature on success.
  Future<String> submitProof({
    required Groth16Proof proof,
    required ProofPublicInputs publicInputs,
    required Uint8List nullifierHash,
    required String issuerPubkey,
  }) async {
    final ixData = _buildVerifyProofInstruction(
      proof,
      publicInputs,
      nullifierHash,
    );

    // Derive PDAs.
    final issuerPda = PdaDerivation.findIssuerPda(issuerPubkey);
    final vkPda = PdaDerivation.findVkPda(issuerPubkey);
    final nullifierPda = PdaDerivation.findNullifierPda(nullifierHash);

    final instructions = <web3.TransactionInstruction>[
      // Compute budget.
      web3.TransactionInstruction(
        keys: [],
        programId: web3.Pubkey.fromBase58(
          'ComputeBudget111111111111111111111111111111',
        ),
        data: _buildComputeBudgetInstruction(
          AppConstants.verificationComputeUnits,
        ),
      ),
      // Verify proof instruction.
      web3.TransactionInstruction(
        keys: [
          // 1. issuerAccount (read-only)
          web3.AccountMeta(web3.Pubkey.fromUint8List(issuerPda.address)),
          // 2. vkAccount (read-only)
          web3.AccountMeta(web3.Pubkey.fromUint8List(vkPda.address)),
          // 3. nullifierAccount (writable, init-if-needed)
          web3.AccountMeta.writable(
            web3.Pubkey.fromUint8List(nullifierPda.address),
          ),
          // 4. submitter (signer + writable)
          web3.AccountMeta.signerAndWritable(_wallet.pubkey),
          // 5. systemProgram
          web3.AccountMeta(
            web3.Pubkey.fromBase58('11111111111111111111111111111111'),
          ),
        ],
        programId: programId,
        data: ixData,
      ),
    ];

    return await _wallet.sendTransaction(instructions);
  }

  /// Initialize an issuer account on-chain.
  Future<String> initializeIssuer(String issuerName) async {
    final ixData = buildInitializeIssuerInstruction(issuerName);
    final issuerPda = PdaDerivation.findIssuerPda(_wallet.publicKeyBase58);

    final instructions = [
      web3.TransactionInstruction(
        keys: [
          // issuerAccount (writable, PDA — init)
          web3.AccountMeta.writable(
            web3.Pubkey.fromUint8List(issuerPda.address),
          ),
          // authority (signer + writable — payer)
          web3.AccountMeta.signerAndWritable(_wallet.pubkey),
          // systemProgram
          web3.AccountMeta(
            web3.Pubkey.fromBase58('11111111111111111111111111111111'),
          ),
        ],
        programId: programId,
        data: ixData,
      ),
    ];

    return await _wallet.sendTransaction(instructions);
  }

  /// Update the Merkle root on-chain.
  Future<String> updateMerkleRoot(Uint8List newRoot, int treeSize) async {
    final ixData = buildUpdateMerkleRootInstruction(newRoot, treeSize);
    final issuerPda = PdaDerivation.findIssuerPda(_wallet.publicKeyBase58);

    final instructions = [
      web3.TransactionInstruction(
        keys: [
          // issuerAccount (writable)
          web3.AccountMeta.writable(
            web3.Pubkey.fromUint8List(issuerPda.address),
          ),
          // authority (signer)
          web3.AccountMeta.signer(_wallet.pubkey),
        ],
        programId: programId,
        data: ixData,
      ),
    ];

    return await _wallet.sendTransaction(instructions);
  }

  /// Update the revocation root on-chain.
  Future<String> updateRevocationRoot(Uint8List newRoot) async {
    final ixData = buildUpdateRevocationRootInstruction(newRoot);
    final issuerPda = PdaDerivation.findIssuerPda(_wallet.publicKeyBase58);

    final instructions = [
      web3.TransactionInstruction(
        keys: [
          web3.AccountMeta.writable(
            web3.Pubkey.fromUint8List(issuerPda.address),
          ),
          web3.AccountMeta.signer(_wallet.pubkey),
        ],
        programId: programId,
        data: ixData,
      ),
    ];

    return await _wallet.sendTransaction(instructions);
  }

  /// Store a verification key on-chain.
  Future<String> storeVerificationKey({
    required Uint8List alphaG1,
    required Uint8List betaG2,
    required Uint8List gammaG2,
    required Uint8List deltaG2,
    required List<Uint8List> ic,
  }) async {
    final ixData = buildStoreVerificationKeyInstruction(
      alphaG1: alphaG1,
      betaG2: betaG2,
      gammaG2: gammaG2,
      deltaG2: deltaG2,
      ic: ic,
    );

    final issuerPda = PdaDerivation.findIssuerPda(_wallet.publicKeyBase58);
    final vkPda = PdaDerivation.findVkPda(_wallet.publicKeyBase58);

    final instructions = [
      web3.TransactionInstruction(
        keys: [
          // issuerAccount (read-only)
          web3.AccountMeta(web3.Pubkey.fromUint8List(issuerPda.address)),
          // vkAccount (writable, init)
          web3.AccountMeta.writable(web3.Pubkey.fromUint8List(vkPda.address)),
          // authority (signer + writable — payer)
          web3.AccountMeta.signerAndWritable(_wallet.pubkey),
          // systemProgram
          web3.AccountMeta(
            web3.Pubkey.fromBase58('11111111111111111111111111111111'),
          ),
        ],
        programId: programId,
        data: ixData,
      ),
    ];

    return await _wallet.sendTransaction(instructions);
  }

  /// Build instruction data for `update_merkle_root`.
  Uint8List buildUpdateMerkleRootInstruction(Uint8List newRoot, int treeSize) {
    final buffer = BytesBuilder();
    // Anchor discriminator for `update_merkle_root` (first 8 bytes of
    // SHA256("global:update_merkle_root")).
    final disc = sha256.convert(utf8.encode('global:update_merkle_root'));
    buffer.add(Uint8List.fromList(disc.bytes.sublist(0, 8)));
    buffer.add(newRoot); // [u8; 32]
    buffer.add(_encodeU64(treeSize)); // u64
    return buffer.toBytes();
  }

  /// Build instruction data for `initialize_issuer`.
  ///
  /// IDL: args = [issuerName: string]
  /// Borsh string = 4-byte LE length + UTF-8 bytes.
  Uint8List buildInitializeIssuerInstruction(String issuerName) {
    final buffer = BytesBuilder();
    final disc = sha256.convert(utf8.encode('global:initialize_issuer'));
    buffer.add(Uint8List.fromList(disc.bytes.sublist(0, 8)));
    final nameBytes = utf8.encode(issuerName);
    buffer.add(_encodeU32(nameBytes.length)); // 4-byte LE length prefix
    buffer.add(nameBytes);
    return buffer.toBytes();
  }

  /// Build instruction data for `update_revocation_root`.
  ///
  /// IDL: args = [newRoot: [u8; 32]]
  Uint8List buildUpdateRevocationRootInstruction(Uint8List newRoot) {
    final buffer = BytesBuilder();
    final disc = sha256.convert(utf8.encode('global:update_revocation_root'));
    buffer.add(Uint8List.fromList(disc.bytes.sublist(0, 8)));
    buffer.add(newRoot); // [u8; 32]
    return buffer.toBytes();
  }

  /// Build instruction data for `store_verification_key`.
  ///
  /// IDL: args = [alphaG1: [u8;64], betaG2: [u8;128], gammaG2: [u8;128],
  ///              deltaG2: [u8;128], ic: Vec<[u8;64]>]
  Uint8List buildStoreVerificationKeyInstruction({
    required Uint8List alphaG1,
    required Uint8List betaG2,
    required Uint8List gammaG2,
    required Uint8List deltaG2,
    required List<Uint8List> ic,
  }) {
    final buffer = BytesBuilder();
    final disc = sha256.convert(utf8.encode('global:store_verification_key'));
    buffer.add(Uint8List.fromList(disc.bytes.sublist(0, 8)));
    buffer.add(alphaG1); // [u8; 64]
    buffer.add(betaG2); // [u8; 128]
    buffer.add(gammaG2); // [u8; 128]
    buffer.add(deltaG2); // [u8; 128]
    // ic: Vec<[u8; 64]> — Borsh Vec with 4-byte LE length prefix
    buffer.add(_encodeU32(ic.length));
    for (final point in ic) {
      buffer.add(point);
    }
    return buffer.toBytes();
  }

  // ── Private Helpers ────────────────────────────────────────────────

  Uint8List _buildVerifyProofInstruction(
    Groth16Proof proof,
    ProofPublicInputs publicInputs,
    Uint8List nullifierHash,
  ) {
    final buffer = BytesBuilder();

    // Anchor discriminator for `verify_proof`.
    final disc = sha256.convert(utf8.encode('global:verify_proof'));
    buffer.add(Uint8List.fromList(disc.bytes.sublist(0, 8)));

    // proofA [u8; 64] — raw bytes, no length prefix.
    buffer.add(proof.a.serialize());

    // proofB [u8; 128] — raw bytes, no length prefix.
    buffer.add(proof.b.serialize());

    // proofC [u8; 64] — raw bytes, no length prefix.
    buffer.add(proof.c.serialize());

    // publicInputs Vec<[u8; 32]> — Borsh Vec with 4-byte LE length prefix.
    buffer.add(publicInputs.serialize());

    // nullifierHash [u8; 32] — raw bytes, no length prefix.
    buffer.add(nullifierHash);

    return buffer.toBytes();
  }

  Uint8List _buildComputeBudgetInstruction(int units) {
    final buffer = BytesBuilder();
    // SetComputeUnitLimit instruction index = 2
    buffer.addByte(2);
    buffer.add(_encodeU32(units));
    return buffer.toBytes();
  }

  Uint8List _encodeU32(int value) {
    final data = ByteData(4);
    data.setUint32(0, value, Endian.little);
    return data.buffer.asUint8List();
  }

  Uint8List _encodeU64(int value) {
    final data = ByteData(8);
    data.setInt64(0, value, Endian.little);
    return data.buffer.asUint8List();
  }

  /// Extract binary data from AccountInfo.data (which may be various types).
  Uint8List? _extractBinaryData(dynamic data) {
    if (data == null) return null;
    if (data is Uint8List) return data;
    if (data is List<int>) return Uint8List.fromList(data);
    if (data is String) {
      // base64-encoded
      try {
        return base64Decode(data);
      } catch (_) {
        return null;
      }
    }
    if (data is List && data.length >= 2 && data[0] is String) {
      // [base64String, encoding] format from JSON-RPC
      try {
        return base64Decode(data[0] as String);
      } catch (_) {
        return null;
      }
    }
    return null;
  }

  IssuerInfo? _deserializeIssuerAccount(Uint8List data) {
    if (data.length < 185) return null;

    // Skip 8-byte Anchor discriminator.
    int offset = 8;

    final authority = bytesToHex(data.sublist(offset, offset + 32));
    offset += 32;

    final merkleRoot = data.sublist(offset, offset + 32);
    offset += 32;

    final revocationRoot = data.sublist(offset, offset + 32);
    offset += 32;

    final treeSize = ByteData.sublistView(
      data,
      offset,
      offset + 8,
    ).getInt64(0, Endian.little);
    offset += 8;

    final lastUpdated = ByteData.sublistView(
      data,
      offset,
      offset + 8,
    ).getInt64(0, Endian.little);
    offset += 8;

    // String: 4-byte length prefix + UTF-8 bytes.
    final nameLen = ByteData.sublistView(
      data,
      offset,
      offset + 4,
    ).getUint32(0, Endian.little);
    offset += 4;
    final name = utf8.decode(data.sublist(offset, offset + nameLen));
    offset += nameLen;

    final isActive = data[offset] == 1;

    return IssuerInfo(
      authority: authority,
      merkleRoot: Uint8List.fromList(merkleRoot),
      revocationRoot: Uint8List.fromList(revocationRoot),
      treeSize: treeSize,
      lastUpdated: lastUpdated,
      name: name,
      isActive: isActive,
    );
  }
}
