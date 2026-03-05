/// Wallet management service: keypair loading, signing, and balance queries.
///
/// Loads the Solana keypair from the bundled asset file and provides
/// signing capabilities using the `solana_web3` package.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/services.dart' show rootBundle;
import 'package:solana_web3/solana_web3.dart' as web3;

import '../core/constants.dart';

class WalletService {
  WalletService._();

  static WalletService? _instance;
  static WalletService get instance => _instance ??= WalletService._();

  web3.Keypair? _keypair;
  web3.Connection? _connection;

  /// Whether the wallet has been initialized.
  bool get isInitialized => _keypair != null;

  /// The wallet's public key in Base58 format.
  String get publicKeyBase58 {
    if (_keypair == null) throw StateError('Wallet not initialized');
    return _keypair!.pubkey.toBase58();
  }

  /// The wallet's public key.
  web3.Pubkey get pubkey {
    if (_keypair == null) throw StateError('Wallet not initialized');
    return _keypair!.pubkey;
  }

  /// The underlying keypair.
  web3.Keypair get keypair {
    if (_keypair == null) throw StateError('Wallet not initialized');
    return _keypair!;
  }

  /// The active Solana connection.
  web3.Connection get connection {
    _connection ??= web3.Connection(web3.Cluster.devnet);
    return _connection!;
  }

  // ── Initialization ─────────────────────────────────────────────────

  /// Load the keypair from the bundled asset file.
  Future<void> initialize() async {
    if (_keypair != null) return; // Already initialized.

    final jsonString = await rootBundle.loadString(
      'assets/solana-wallet-keypair.json',
    );
    final List<dynamic> jsonBytes = jsonDecode(jsonString);
    final secretKey = Uint8List.fromList(
      jsonBytes.map((e) => e as int).toList(),
    );

    _keypair = web3.Keypair.fromSeckeySync(secretKey);
    _connection = web3.Connection(web3.Cluster.devnet);
  }

  /// Initialize from raw secret key bytes (for testing).
  void initializeFromBytes(Uint8List secretKey) {
    _keypair = web3.Keypair.fromSeckeySync(secretKey);
    _connection = web3.Connection(web3.Cluster.devnet);
  }

  // ── Balance ────────────────────────────────────────────────────────

  /// Get the wallet's SOL balance in lamports.
  Future<int> getBalanceLamports() async {
    if (_keypair == null) throw StateError('Wallet not initialized');
    final balance = await connection.getBalance(_keypair!.pubkey);
    return balance.toInt();
  }

  /// Get the wallet's SOL balance as a double.
  Future<double> getBalanceSol() async {
    final lamports = await getBalanceLamports();
    return lamports / 1e9;
  }

  // ── Airdrop (Devnet only) ──────────────────────────────────────────

  /// Request a devnet airdrop of [solAmount] SOL.
  Future<String> requestAirdrop({double solAmount = 1.0}) async {
    if (_keypair == null) throw StateError('Wallet not initialized');
    final lamports = (solAmount * 1e9).toInt();
    return await connection.requestAirdrop(_keypair!.pubkey, lamports);
  }

  // ── Account Info ───────────────────────────────────────────────────

  /// Fetch account info for a given public key.
  Future<web3.AccountInfo?> getAccountInfo(web3.Pubkey pubkey) async {
    return await connection.getAccountInfo(pubkey);
  }

  /// Fetch account info for a Base58-encoded public key.
  Future<web3.AccountInfo?> getAccountInfoBase58(String base58Pubkey) async {
    final pubkey = web3.Pubkey.fromBase58(base58Pubkey);
    return await connection.getAccountInfo(pubkey);
  }

  // ── Transaction Sending ────────────────────────────────────────────

  /// Build, sign, and send a transaction with the wallet's keypair.
  ///
  /// Returns the transaction signature.
  Future<String> sendTransaction(
    List<web3.TransactionInstruction> instructions,
  ) async {
    if (_keypair == null) throw StateError('Wallet not initialized');

    final blockhashInfo = await connection.getLatestBlockhash();

    final tx = web3.Transaction.v0(
      payer: _keypair!.pubkey,
      recentBlockhash: blockhashInfo.blockhash,
      instructions: instructions,
    );

    tx.sign([_keypair!]);

    final signature = await connection.sendAndConfirmTransaction(tx);
    return signature;
  }

  /// Build a TransactionInstruction for the ZK-DocAuth program.
  web3.TransactionInstruction buildProgramInstruction({
    required List<web3.AccountMeta> accounts,
    required Uint8List data,
  }) {
    return web3.TransactionInstruction(
      keys: accounts,
      programId: web3.Pubkey.fromBase58(AppConstants.programId),
      data: data,
    );
  }

  // ── Cleanup ────────────────────────────────────────────────────────

  void dispose() {
    _connection?.dispose();
    _connection = null;
  }
}
