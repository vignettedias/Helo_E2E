/// Plaintext padding — port of `helo_ref/padding.py`.
///
///     padded = payload ‖ 0x80 ‖ 0x00*      (length rounded up to a bucket)
///
/// Applied before encryption, removed after authentication, so the relay
/// learns only the bucket, never the exact length. This hides length within a
/// bucket; it does not hide timing, frequency, or who talks to whom.
library;

import 'dart:typed_data';

import 'errors.dart';

const int padMarker = 0x80;
const int maxPaddedLen = 64 * 1024 - 16;

enum PaddingMode { none, block, pow2, padme }

class PaddingPolicy {
  const PaddingPolicy(this.mode, [this.size = 0]);

  final PaddingMode mode;

  /// Block size for [PaddingMode.block]; minimum for [PaddingMode.pow2].
  final int size;

  /// Padded length for [n] bytes INCLUDING the 0x80 marker (n >= 1).
  int targetLength(int n) {
    if (n < 1) throw ArgumentError('length includes the marker, so it is >= 1');
    switch (mode) {
      case PaddingMode.none:
        return n;
      case PaddingMode.block:
        return ((n + size - 1) ~/ size) * size;
      case PaddingMode.pow2:
        int target = size < 1 ? 1 : size;
        while (target < n) {
          target <<= 1;
        }
        return target;
      case PaddingMode.padme:
        return padme(n);
    }
  }

  String get label => switch (mode) {
        PaddingMode.none => 'none',
        PaddingMode.padme => 'padme',
        PaddingMode.block => 'block-$size',
        PaddingMode.pow2 => 'pow2-$size',
      };
}

/// Padmé (Nikitin et al., PETS 2019): E = floor(log2 L), S = floor(log2 E)+1,
/// round L up to a multiple of 2^(E-S).
int padme(int length) {
  if (length < 2) return length;
  final int e = length.bitLength - 1;
  final int s = e.bitLength;
  final int mask = (1 << (e - s)) - 1;
  return (length + mask) & ~mask;
}

const PaddingPolicy defaultPaddingPolicy = PaddingPolicy(PaddingMode.block, 256);

const Map<String, PaddingPolicy> paddingPolicies = <String, PaddingPolicy>{
  'none': PaddingPolicy(PaddingMode.none),
  'block-160': PaddingPolicy(PaddingMode.block, 160),
  'block-256': PaddingPolicy(PaddingMode.block, 256),
  'pow2-256': PaddingPolicy(PaddingMode.pow2, 256),
  'padme': PaddingPolicy(PaddingMode.padme),
};

Uint8List pad(List<int> payload, [PaddingPolicy policy = defaultPaddingPolicy]) {
  final int target = policy.targetLength(payload.length + 1);
  if (target > maxPaddedLen) {
    throw InvalidEncodingError(
        'padded message would be $target bytes; limit is $maxPaddedLen');
  }
  final Uint8List out = Uint8List(target)
    ..setAll(0, payload)
    ..[payload.length] = padMarker;
  return out;
}

/// Strip padding. Anything not of the form `… 0x80 0x00*` is rejected.
Uint8List unpad(List<int> padded) {
  int end = padded.length;
  while (end > 0 && padded[end - 1] == 0x00) {
    end -= 1;
  }
  if (end == 0 || padded[end - 1] != padMarker) {
    throw const InvalidEncodingError(
        'invalid padding: no 0x80 marker before the zero fill');
  }
  return Uint8List.fromList(padded.sublist(0, end - 1));
}
