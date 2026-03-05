/// Typed exceptions for ZK-DocAuth.
library;

sealed class ZKDocAuthException implements Exception {
  const ZKDocAuthException(this.message);
  final String message;

  @override
  String toString() => '$runtimeType: $message';
}

class InvalidCredentialException extends ZKDocAuthException {
  const InvalidCredentialException(super.message);
}

class MerkleTreeException extends ZKDocAuthException {
  const MerkleTreeException(super.message);
}

class ProofGenerationException extends ZKDocAuthException {
  const ProofGenerationException(super.message);
}

class ProofVerificationException extends ZKDocAuthException {
  const ProofVerificationException(super.message);
}

class SolanaTransactionException extends ZKDocAuthException {
  const SolanaTransactionException(super.message);
}

class WalletException extends ZKDocAuthException {
  const WalletException(super.message);
}

class PoseidonHashException extends ZKDocAuthException {
  const PoseidonHashException(super.message);
}

class FieldEncodingException extends ZKDocAuthException {
  const FieldEncodingException(super.message);
}
