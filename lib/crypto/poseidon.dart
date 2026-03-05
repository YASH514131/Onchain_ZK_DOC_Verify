/// Poseidon hash function over the BN254 scalar field.
///
/// This is a pure-Dart implementation of the Poseidon permutation with
/// t = 3 (2 inputs + 1 capacity element), suitable for Merkle trees and
/// credential commitments inside ZK circuits.
///
/// Security level: 128-bit (collision resistance over ~254-bit field).
///
/// Reference: Grassi et al., "Poseidon: A New Hash Function for
/// Zero-Knowledge Proof Systems", USENIX Security 2021.
library;

import '../core/utils.dart';
import '../core/exceptions.dart';
import 'poseidon_constants.dart';

class PoseidonHash {
  PoseidonHash._();

  /// The BN254 scalar field prime.
  static final BigInt _p = bn254Prime;

  /// Number of full rounds.
  static const int _rF = 8;

  /// Number of partial rounds.
  static const int _rP = 57;

  /// Width of the internal state (t = nInputs + 1).
  static int _width(int nInputs) => nInputs + 1;

  // ── Public API ──────────────────────────────────────────────────────

  /// Poseidon hash of one field element.
  static BigInt hash1(BigInt input) => _poseidon([input]);

  /// Poseidon hash of two field elements (used for Merkle tree nodes).
  static BigInt hash2(BigInt left, BigInt right) => _poseidon([left, right]);

  /// Poseidon hash of an arbitrary number of field elements (1..12).
  static BigInt hashMany(List<BigInt> inputs) {
    if (inputs.isEmpty || inputs.length > 12) {
      throw const PoseidonHashException('Poseidon supports 1 to 12 inputs');
    }
    return _poseidon(inputs);
  }

  // ── Core Permutation ───────────────────────────────────────────────

  static BigInt _poseidon(List<BigInt> inputs) {
    final t = _width(inputs.length);
    final constants = PoseidonConstants.forWidth(t);

    // Initialize state: [0, input_0, input_1, ...]
    List<BigInt> state = List<BigInt>.filled(t, BigInt.zero);
    for (int i = 0; i < inputs.length; i++) {
      state[i + 1] = inputs[i] % _p;
    }

    // Round counter for round constants.
    int rcIdx = 0;

    // ── First half of full rounds ──
    for (int r = 0; r < _rF ~/ 2; r++) {
      // Add round constants.
      for (int i = 0; i < t; i++) {
        state[i] = (state[i] + constants.roundConstants[rcIdx]) % _p;
        rcIdx++;
      }
      // Full S-box: x^5 on every element.
      for (int i = 0; i < t; i++) {
        state[i] = _sbox(state[i]);
      }
      // MDS mixing.
      state = _mdsMultiply(state, constants.mdsMatrix, t);
    }

    // ── Partial rounds ──
    for (int r = 0; r < _rP; r++) {
      // Add round constants.
      for (int i = 0; i < t; i++) {
        state[i] = (state[i] + constants.roundConstants[rcIdx]) % _p;
        rcIdx++;
      }
      // Partial S-box: x^5 only on the first element.
      state[0] = _sbox(state[0]);
      // MDS mixing.
      state = _mdsMultiply(state, constants.mdsMatrix, t);
    }

    // ── Second half of full rounds ──
    for (int r = 0; r < _rF ~/ 2; r++) {
      // Add round constants.
      for (int i = 0; i < t; i++) {
        state[i] = (state[i] + constants.roundConstants[rcIdx]) % _p;
        rcIdx++;
      }
      // Full S-box.
      for (int i = 0; i < t; i++) {
        state[i] = _sbox(state[i]);
      }
      // MDS mixing.
      state = _mdsMultiply(state, constants.mdsMatrix, t);
    }

    // Output is state[0].
    return state[0];
  }

  /// S-box: x -> x^5 mod p.
  static BigInt _sbox(BigInt x) {
    final x2 = (x * x) % _p;
    final x4 = (x2 * x2) % _p;
    return (x4 * x) % _p;
  }

  /// Multiply state vector by the MDS matrix.
  static List<BigInt> _mdsMultiply(
    List<BigInt> state,
    List<List<BigInt>> mds,
    int t,
  ) {
    final result = List<BigInt>.filled(t, BigInt.zero);
    for (int i = 0; i < t; i++) {
      BigInt acc = BigInt.zero;
      for (int j = 0; j < t; j++) {
        acc = (acc + mds[i][j] * state[j]) % _p;
      }
      result[i] = acc;
    }
    return result;
  }
}
