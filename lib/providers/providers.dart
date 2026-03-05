/// ChangeNotifier-based providers for the application state.
library;

import 'package:flutter/foundation.dart';

import '../core/utils.dart';
import '../crypto/merkle_tree.dart';
import '../models/models.dart';
import '../services/credential_service.dart';
import '../services/proof_service.dart';
import '../services/solana_service.dart';
import '../services/wallet_service.dart';

// ─────────────────────────────────────────────────────────────────────────────
// Credential Provider
// ─────────────────────────────────────────────────────────────────────────────

class CredentialProvider extends ChangeNotifier {
  CredentialProvider({CredentialService? credentialService})
    : _credentialService = credentialService ?? CredentialService();

  final CredentialService _credentialService;

  Credential? _credential;
  BigInt? _commitment;
  String? _errorMessage;
  bool _isLoading = false;

  Credential? get credential => _credential;
  BigInt? get commitment => _commitment;
  String? get errorMessage => _errorMessage;
  bool get isLoading => _isLoading;
  bool get hasCredential => _credential != null;

  /// Issue a new credential from raw fields.
  void issueCredential({
    required String name,
    required int dob,
    required String nationality,
    required int nationalityCode,
    required String documentId,
    required int expiry,
    required String issuerPublicKey,
  }) {
    _isLoading = true;
    _errorMessage = null;
    notifyListeners();

    try {
      _credential = Credential(
        name: name,
        dob: dob,
        nationality: nationality,
        nationalityCode: nationalityCode,
        documentId: documentId,
        expiry: expiry,
        issuedAt: DateTime.now().millisecondsSinceEpoch ~/ 1000,
        issuerPublicKey: issuerPublicKey,
      );

      // Validate
      final errors = _credentialService.validateCredential(_credential!);
      if (errors.isNotEmpty) {
        _errorMessage = errors.join('; ');
        _credential = null;
        return;
      }

      // Compute Poseidon commitment.
      _commitment = _credentialService.computeCommitment(_credential!);
    } catch (e) {
      _errorMessage = 'Credential creation failed: $e';
      _credential = null;
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  /// Save the current credential to secure storage.
  Future<void> saveCredential(String id) async {
    if (_credential == null) return;
    await _credentialService.storeCredential(_credential!, id);
  }

  /// Load a credential from secure storage.
  Future<void> loadCredential(String id) async {
    _isLoading = true;
    notifyListeners();

    try {
      _credential = await _credentialService.loadCredential(id);
      if (_credential != null) {
        _commitment = _credentialService.computeCommitment(_credential!);
      }
    } catch (e) {
      _errorMessage = 'Failed to load credential: $e';
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  void clear() {
    _credential = null;
    _commitment = null;
    _errorMessage = null;
    notifyListeners();
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Proof Provider
// ─────────────────────────────────────────────────────────────────────────────

class ProofProvider extends ChangeNotifier {
  ProofProvider({ZKProofService? proofService})
    : _proofService = proofService ?? ZKProofService();

  final ZKProofService _proofService;

  // Merkle tree for credential insertion (Issuer-side simulation).
  final MerkleTree _merkleTree = MerkleTree();

  ProofOutput? _proofOutput;
  MerkleProofData? _merkleProof;
  String? _errorMessage;
  bool _isGenerating = false;
  Duration? _proofGenerationTime;

  ProofOutput? get proofOutput => _proofOutput;
  MerkleProofData? get merkleProof => _merkleProof;
  String? get errorMessage => _errorMessage;
  bool get isGenerating => _isGenerating;
  Duration? get proofGenerationTime => _proofGenerationTime;
  BigInt get merkleRoot => _merkleTree.root;
  int get treeSize => _merkleTree.leafCount;

  /// Insert a credential commitment into the Merkle tree (Issuer action).
  int insertCredential(BigInt commitment) {
    final index = _merkleTree.insertLeaf(commitment);
    notifyListeners();
    return index;
  }

  /// Generate a Merkle proof for a leaf at [index].
  void prepareMerkleProof(int leafIndex) {
    try {
      _merkleProof = _merkleTree.generateProof(leafIndex);
      _errorMessage = null;
    } catch (e) {
      _errorMessage = 'Merkle proof generation failed: $e';
    }
    notifyListeners();
  }

  /// Generate a ZK proof for the given claim.
  Future<void> generateProof({
    required Credential credential,
    required ClaimType claimType,
    int? minAge,
    int? expectedNationalityCode,
  }) async {
    if (_merkleProof == null) {
      _errorMessage = 'Merkle proof not prepared';
      notifyListeners();
      return;
    }

    _isGenerating = true;
    _errorMessage = null;
    _proofOutput = null;
    notifyListeners();

    try {
      final stopwatch = Stopwatch()..start();

      final request = ProofRequest(
        credential: credential,
        merkleProof: _merkleProof!,
        claimType: claimType,
        minAge: minAge,
        expectedNationalityCode: expectedNationalityCode,
      );

      _proofOutput = await _proofService.generateProof(request);

      stopwatch.stop();
      _proofGenerationTime = stopwatch.elapsed;
    } catch (e) {
      _errorMessage = 'Proof generation failed: $e';
    } finally {
      _isGenerating = false;
      notifyListeners();
    }
  }

  /// Revoke a credential at [leafIndex].
  void revokeCredential(int leafIndex) {
    _merkleTree.revokeLeaf(leafIndex);
    notifyListeners();
  }

  void clear() {
    _proofOutput = null;
    _merkleProof = null;
    _errorMessage = null;
    _proofGenerationTime = null;
    notifyListeners();
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Wallet Provider
// ─────────────────────────────────────────────────────────────────────────────

class WalletProvider extends ChangeNotifier {
  WalletProvider({WalletService? walletService})
    : _walletService = walletService ?? WalletService.instance;

  final WalletService _walletService;

  bool _isInitialized = false;
  bool _isLoading = false;
  double _balanceSol = 0.0;
  String? _publicKey;
  String? _errorMessage;

  bool get isInitialized => _isInitialized;
  bool get isLoading => _isLoading;
  double get balanceSol => _balanceSol;
  String? get publicKey => _publicKey;
  String? get errorMessage => _errorMessage;

  /// Initialize the wallet from the bundled keypair asset.
  Future<void> initialize() async {
    if (_isInitialized) return;
    _isLoading = true;
    _errorMessage = null;
    notifyListeners();

    try {
      await _walletService.initialize();
      _publicKey = _walletService.publicKeyBase58;
      _isInitialized = true;
      await refreshBalance();
    } catch (e) {
      _errorMessage = 'Wallet init failed: $e';
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }

  /// Refresh the SOL balance.
  Future<void> refreshBalance() async {
    if (!_isInitialized) return;
    try {
      _balanceSol = await _walletService.getBalanceSol();
      _errorMessage = null;
    } catch (e) {
      _errorMessage = 'Balance fetch failed: $e';
    }
    notifyListeners();
  }

  /// Request a devnet airdrop.
  Future<void> requestAirdrop({double amount = 1.0}) async {
    if (!_isInitialized) return;
    _isLoading = true;
    _errorMessage = null;
    notifyListeners();

    try {
      await _walletService.requestAirdrop(solAmount: amount);
      // Wait a moment for the airdrop to confirm before refreshing.
      await Future<void>.delayed(const Duration(seconds: 2));
      await refreshBalance();
    } catch (e) {
      _errorMessage = 'Airdrop failed: $e';
    } finally {
      _isLoading = false;
      notifyListeners();
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Solana Provider
// ─────────────────────────────────────────────────────────────────────────────

class SolanaProvider extends ChangeNotifier {
  SolanaProvider({SolanaService? solanaService})
    : _solanaService = solanaService ?? SolanaService();

  final SolanaService _solanaService;

  String? _transactionSignature;
  String? _errorMessage;
  bool _isSubmitting = false;
  IssuerInfo? _issuerInfo;

  String? get transactionSignature => _transactionSignature;
  String? get errorMessage => _errorMessage;
  bool get isSubmitting => _isSubmitting;
  IssuerInfo? get issuerInfo => _issuerInfo;
  String get cluster => _solanaService.rpcUrl;

  /// Submit a proof to the Solana program.
  Future<void> submitProof({
    required ProofOutput proofOutput,
    required String issuerPubkey,
  }) async {
    _isSubmitting = true;
    _errorMessage = null;
    _transactionSignature = null;
    notifyListeners();

    try {
      final nullifierHashBytes = bigIntToBytes32(proofOutput.nullifierHash);

      _transactionSignature = await _solanaService.submitProof(
        proof: proofOutput.proof,
        publicInputs: proofOutput.publicInputs,
        nullifierHash: nullifierHashBytes,
        issuerPubkey: issuerPubkey,
      );
    } catch (e) {
      _errorMessage = 'Transaction submission failed: $e';
    } finally {
      _isSubmitting = false;
      notifyListeners();
    }
  }

  /// Initialize an issuer on-chain.
  Future<void> initializeIssuer(String issuerName) async {
    _isSubmitting = true;
    _errorMessage = null;
    _transactionSignature = null;
    notifyListeners();

    try {
      _transactionSignature = await _solanaService.initializeIssuer(issuerName);
    } catch (e) {
      _errorMessage = 'Initialize issuer failed: $e';
    } finally {
      _isSubmitting = false;
      notifyListeners();
    }
  }

  /// Update merkle root on-chain.
  Future<void> updateMerkleRoot(Uint8List newRoot, int treeSize) async {
    _isSubmitting = true;
    _errorMessage = null;
    notifyListeners();

    try {
      _transactionSignature = await _solanaService.updateMerkleRoot(
        newRoot,
        treeSize,
      );
    } catch (e) {
      _errorMessage = 'Update merkle root failed: $e';
    } finally {
      _isSubmitting = false;
      notifyListeners();
    }
  }

  /// Fetch issuer account info from on-chain.
  Future<void> fetchIssuerInfo(String issuerPubkey) async {
    try {
      _issuerInfo = await _solanaService.fetchIssuerAccount(issuerPubkey);
    } catch (e) {
      _errorMessage = 'Failed to fetch issuer info: $e';
    }
    notifyListeners();
  }

  void clear() {
    _transactionSignature = null;
    _errorMessage = null;
    _issuerInfo = null;
    notifyListeners();
  }
}
