/// Utility helpers: field encoding, byte manipulation, date math.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import 'constants.dart';
import 'exceptions.dart';

// ── BigInt Helpers ───────────────────────────────────────────────────────────

/// The BN254 scalar field prime.
final BigInt bn254Prime = BigInt.parse(
  AppConstants.bn254ScalarFieldHex,
  radix: 16,
);

/// Reduce [value] modulo the BN254 scalar field.
BigInt fieldReduce(BigInt value) {
  final r = value % bn254Prime;
  return r < BigInt.zero ? r + bn254Prime : r;
}

// ── Field Encoding ──────────────────────────────────────────────────────────

/// Pack a UTF-8 string into a single field element (little-endian byte packing).
///
/// Strings > 31 bytes are SHA-256 hashed first, then the digest is packed.
BigInt fieldEncodeString(String s) {
  if (s.isEmpty) return BigInt.zero;
  Uint8List bytes = Uint8List.fromList(utf8.encode(s));

  if (bytes.length > AppConstants.maxBytesPerFieldElement) {
    // Hash down to 32 bytes then take first 31 to stay within field.
    final digest = sha256.convert(bytes).bytes;
    bytes = Uint8List.fromList(digest.sublist(0, 31));
  }

  // Little-endian packing: sum(bytes[i] * 256^i)
  BigInt result = BigInt.zero;
  for (int i = 0; i < bytes.length; i++) {
    result += BigInt.from(bytes[i]) << (8 * i);
  }

  if (result >= bn254Prime) {
    throw const FieldEncodingException(
      'Encoded value exceeds BN254 scalar field',
    );
  }
  return result;
}

/// Encode an integer date (YYYYMMDD) as a field element.
BigInt fieldEncodeDate(int yyyymmdd) {
  if (yyyymmdd < 0 || yyyymmdd > 99999999) {
    throw const FieldEncodingException('Date must be in YYYYMMDD format');
  }
  return BigInt.from(yyyymmdd);
}

/// Encode a country code as a field element.
BigInt fieldEncodeCountry(int isoNumeric) {
  if (isoNumeric < 0 || isoNumeric > 999) {
    throw const FieldEncodingException('Invalid ISO 3166-1 numeric code');
  }
  return BigInt.from(isoNumeric);
}

// ── Byte Conversions ────────────────────────────────────────────────────────

/// Convert a [BigInt] to a 32-byte big-endian [Uint8List].
Uint8List bigIntToBytes32(BigInt value) {
  final hexStr = value.toRadixString(16).padLeft(64, '0');
  final bytes = Uint8List(32);
  for (int i = 0; i < 32; i++) {
    bytes[i] = int.parse(hexStr.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return bytes;
}

/// Convert a 32-byte big-endian [Uint8List] to a [BigInt].
BigInt bytes32ToBigInt(Uint8List bytes) {
  if (bytes.length != 32) {
    throw const FieldEncodingException('Expected exactly 32 bytes');
  }
  BigInt result = BigInt.zero;
  for (int i = 0; i < 32; i++) {
    result = (result << 8) | BigInt.from(bytes[i]);
  }
  return result;
}

/// Hex-encode bytes with no prefix.
String bytesToHex(Uint8List bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

/// Decode a hex string to bytes.
Uint8List hexToBytes(String hex) {
  final clean = hex.startsWith('0x') ? hex.substring(2) : hex;
  final len = clean.length ~/ 2;
  final bytes = Uint8List(len);
  for (int i = 0; i < len; i++) {
    bytes[i] = int.parse(clean.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return bytes;
}

// ── Date Helpers ────────────────────────────────────────────────────────────

/// Extract the year from a YYYYMMDD integer.
int extractYear(int yyyymmdd) => yyyymmdd ~/ 10000;

/// Extract the month from a YYYYMMDD integer.
int extractMonth(int yyyymmdd) => (yyyymmdd ~/ 100) % 100;

/// Extract the day from a YYYYMMDD integer.
int extractDay(int yyyymmdd) => yyyymmdd % 100;

/// Get today's date as YYYYMMDD integer.
int todayAsYYYYMMDD() {
  final now = DateTime.now();
  return now.year * 10000 + now.month * 100 + now.day;
}

/// Compute age in years given DOB as YYYYMMDD.
int computeAge(int dobYYYYMMDD, {int? referenceDate}) {
  final ref = referenceDate ?? todayAsYYYYMMDD();
  int age = extractYear(ref) - extractYear(dobYYYYMMDD);
  // Adjust if birthday hasn't occurred yet this year.
  final refMonthDay = ref % 10000;
  final dobMonthDay = dobYYYYMMDD % 10000;
  if (refMonthDay < dobMonthDay) age--;
  return age;
}
