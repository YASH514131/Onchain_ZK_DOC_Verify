/// Credential service: issue, store, retrieve, and compute commitments.
library;

import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import '../core/exceptions.dart';
import '../crypto/poseidon.dart';
import '../models/models.dart';

class CredentialService {
  CredentialService({FlutterSecureStorage? storage})
    : _storage = storage ?? const FlutterSecureStorage();

  final FlutterSecureStorage _storage;

  static const _credentialKeyPrefix = 'zk_credential_';

  // ── Commitment Computation ─────────────────────────────────────────

  /// Compute the Poseidon commitment for a [Credential].
  ///
  /// ```
  /// credential_hash = Poseidon(
  ///   Poseidon(name_fe),
  ///   dob,
  ///   nationality_code,
  ///   Poseidon(document_id_fe),
  ///   expiry
  /// )
  /// ```
  BigInt computeCommitment(Credential credential) {
    final fields = credential.toFieldElements();

    final nameHash = PoseidonHash.hash1(fields['name']!);
    final docIdHash = PoseidonHash.hash1(fields['document_id']!);

    return PoseidonHash.hashMany([
      nameHash,
      fields['dob']!,
      fields['nationality']!,
      docIdHash,
      fields['expiry']!,
    ]);
  }

  /// Compute the nationality hash for a given ISO numeric code.
  BigInt computeNationalityHash(int nationalityCode) {
    return PoseidonHash.hash1(BigInt.from(nationalityCode));
  }

  // ── Secure Storage ─────────────────────────────────────────────────

  /// Store a credential securely on the device.
  Future<void> storeCredential(Credential credential, String id) async {
    final json = jsonEncode(credential.toJson());
    await _storage.write(key: '$_credentialKeyPrefix$id', value: json);
  }

  /// Retrieve a credential from secure storage.
  Future<Credential?> loadCredential(String id) async {
    final json = await _storage.read(key: '$_credentialKeyPrefix$id');
    if (json == null) return null;
    try {
      return Credential.fromJson(jsonDecode(json) as Map<String, dynamic>);
    } catch (e) {
      throw InvalidCredentialException('Failed to deserialize credential: $e');
    }
  }

  /// List all stored credential IDs.
  Future<List<String>> listCredentialIds() async {
    final all = await _storage.readAll();
    return all.keys
        .where((k) => k.startsWith(_credentialKeyPrefix))
        .map((k) => k.substring(_credentialKeyPrefix.length))
        .toList();
  }

  /// Delete a credential from storage.
  Future<void> deleteCredential(String id) async {
    await _storage.delete(key: '$_credentialKeyPrefix$id');
  }

  // ── Validation ─────────────────────────────────────────────────────

  /// Validate that a credential's fields are well-formed.
  List<String> validateCredential(Credential credential) {
    final errors = <String>[];

    if (credential.name.trim().isEmpty) {
      errors.add('Name must not be empty');
    }
    if (credential.dob < 19000101 || credential.dob > 20260101) {
      errors.add('Date of birth out of expected range');
    }
    if (credential.nationalityCode < 1 || credential.nationalityCode > 999) {
      errors.add('Invalid ISO 3166-1 numeric country code');
    }
    if (credential.documentId.trim().isEmpty) {
      errors.add('Document ID must not be empty');
    }
    if (credential.expiry < 20260101) {
      errors.add('Document appears to be expired');
    }

    return errors;
  }
}
