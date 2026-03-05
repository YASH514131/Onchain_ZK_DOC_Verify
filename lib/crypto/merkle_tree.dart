/// Binary Merkle tree using Poseidon hash over the BN254 scalar field.
///
/// - Fixed depth (default 20, supporting 2^20 = 1,048,576 leaves).
/// - Leaves are credential hashes (Poseidon commitments).
/// - Empty leaves are zero.
/// - Internal nodes: Poseidon(left, right).
library;

import '../core/constants.dart';
import '../core/exceptions.dart';
import '../models/models.dart';
import 'poseidon.dart';

class MerkleTree {
  MerkleTree({int? depth})
    : depth = depth ?? AppConstants.merkleTreeDepth,
      _maxLeaves = 1 << (depth ?? AppConstants.merkleTreeDepth) {
    _initZeroHashes();
    _layers = List.generate(this.depth + 1, (_) => <BigInt>[]);
    _layers[0] = []; // leaf layer starts empty
  }

  final int depth;
  final int _maxLeaves;

  /// Pre-computed zero hashes for each level.
  /// zeroHashes[0] = 0 (empty leaf)
  /// zeroHashes[i] = Poseidon(zeroHashes[i-1], zeroHashes[i-1])
  late final List<BigInt> _zeroHashes;

  /// Tree layers: _layers[0] = leaves, _layers[depth] = [root].
  late List<List<BigInt>> _layers;

  /// Number of inserted leaves.
  int get leafCount => _layers[0].length;

  /// Current Merkle root.
  BigInt get root {
    if (leafCount == 0) return _zeroHashes[depth];
    return _computeRoot();
  }

  /// Root as a 32-byte big-endian list (for on-chain comparison).
  List<int> get rootBytes {
    final r = root;
    final hex = r.toRadixString(16).padLeft(64, '0');
    return List<int>.generate(
      32,
      (i) => int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16),
    );
  }

  // ── Initialization ─────────────────────────────────────────────────

  void _initZeroHashes() {
    _zeroHashes = List<BigInt>.filled(depth + 1, BigInt.zero);
    _zeroHashes[0] = BigInt.zero;
    for (int i = 1; i <= depth; i++) {
      _zeroHashes[i] = PoseidonHash.hash2(
        _zeroHashes[i - 1],
        _zeroHashes[i - 1],
      );
    }
  }

  // ── Leaf Operations ────────────────────────────────────────────────

  /// Insert a credential hash as a new leaf. Returns the leaf index.
  int insertLeaf(BigInt leaf) {
    if (leafCount >= _maxLeaves) {
      throw const MerkleTreeException('Merkle tree is full');
    }
    _layers[0].add(leaf);
    return leafCount - 1;
  }

  /// Replace a leaf at [index] (used for revocation -- set to zero).
  void updateLeaf(int index, BigInt newValue) {
    if (index < 0 || index >= leafCount) {
      throw const MerkleTreeException('Leaf index out of bounds');
    }
    _layers[0][index] = newValue;
  }

  /// Revoke a credential by zeroing its leaf.
  void revokeLeaf(int index) => updateLeaf(index, BigInt.zero);

  // ── Proof Generation ───────────────────────────────────────────────

  /// Generate a Merkle inclusion proof for the leaf at [index].
  MerkleProofData generateProof(int index) {
    if (index < 0 || index >= leafCount) {
      throw const MerkleTreeException('Leaf index out of bounds');
    }

    final pathElements = <BigInt>[];
    final pathIndices = <int>[];
    final leaf = _layers[0][index];

    // Rebuild layers from leaves.
    _rebuildLayers();

    int currentIndex = index;
    for (int level = 0; level < depth; level++) {
      final isRight = currentIndex % 2 == 1;
      pathIndices.add(isRight ? 1 : 0);

      final siblingIndex = isRight ? currentIndex - 1 : currentIndex + 1;
      final layer = _layers[level];

      if (siblingIndex < layer.length) {
        pathElements.add(layer[siblingIndex]);
      } else {
        pathElements.add(_zeroHashes[level]);
      }

      currentIndex ~/= 2;
    }

    return MerkleProofData(
      pathElements: pathElements,
      pathIndices: pathIndices,
      leaf: leaf,
      root: root,
    );
  }

  /// Verify a Merkle proof against the current root.
  bool verifyProof(MerkleProofData proof) {
    return _computeRootFromProof(
          proof.leaf,
          proof.pathElements,
          proof.pathIndices,
        ) ==
        root;
  }

  /// Statically verify a Merkle proof against a given root.
  static bool verifyProofAgainstRoot(
    BigInt leaf,
    List<BigInt> pathElements,
    List<int> pathIndices,
    BigInt expectedRoot,
  ) {
    return _computeRootFromProof(leaf, pathElements, pathIndices) ==
        expectedRoot;
  }

  // ── Internal ───────────────────────────────────────────────────────

  BigInt _computeRoot() {
    _rebuildLayers();
    return _layers[depth][0];
  }

  void _rebuildLayers() {
    // Layer 0 = leaves (already populated).
    for (int level = 1; level <= depth; level++) {
      final prevLayer = _layers[level - 1];
      final prevSize = prevLayer.length;
      final thisSize = (prevSize + 1) ~/ 2;
      final thisLayer = <BigInt>[];

      for (int i = 0; i < thisSize; i++) {
        final left = prevLayer[i * 2];
        final right = (i * 2 + 1 < prevSize)
            ? prevLayer[i * 2 + 1]
            : _zeroHashes[level - 1];
        thisLayer.add(PoseidonHash.hash2(left, right));
      }

      // Pad to power of 2 with zero hashes if needed at this level.
      if (thisLayer.isEmpty) {
        thisLayer.add(_zeroHashes[level]);
      }

      _layers[level] = thisLayer;
    }
  }

  static BigInt _computeRootFromProof(
    BigInt leaf,
    List<BigInt> pathElements,
    List<int> pathIndices,
  ) {
    var current = leaf;
    for (int i = 0; i < pathElements.length; i++) {
      if (pathIndices[i] == 0) {
        current = PoseidonHash.hash2(current, pathElements[i]);
      } else {
        current = PoseidonHash.hash2(pathElements[i], current);
      }
    }
    return current;
  }
}
