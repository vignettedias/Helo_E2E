/// Canonical wire encoding — port of `helo_ref/encoding.py`.
///
/// Everything fed into a signature, a KDF, or AEAD associated data must have
/// exactly one byte representation. If two distinct logical structures can
/// serialise to the same bytes, an attacker can substitute one for the other
/// without breaking authentication.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'errors.dart';
import 'primitives.dart';

const int protocolVersion = 1;
const int headerLen = 1 + x25519KeyLen + 4 + 4; // version | dh_pub | pn | n

Uint8List u8(int value) {
  if (value < 0 || value > 0xFF) {
    throw InvalidEncodingError('uint8 out of range: $value');
  }
  return Uint8List.fromList(<int>[value]);
}

Uint8List u32(int value) {
  if (value < 0 || value > 0xFFFFFFFF) {
    throw InvalidEncodingError('uint32 out of range: $value');
  }
  final ByteData d = ByteData(4)..setUint32(0, value);
  return d.buffer.asUint8List();
}

/// Length-prefix with a big-endian uint16.
Uint8List lp(List<int> data) {
  if (data.length > 0xFFFF) {
    throw const InvalidEncodingError('field exceeds max length-prefixed size');
  }
  final ByteData d = ByteData(2)..setUint16(0, data.length);
  return Uint8List.fromList(<int>[...d.buffer.asUint8List(), ...data]);
}

Uint8List concat(List<List<int>> parts) {
  final List<int> out = <int>[];
  for (final List<int> p in parts) {
    out.addAll(p);
  }
  return Uint8List.fromList(out);
}

String b64e(List<int> data) => base64.encode(data);

Uint8List b64d(String text, {int? expectLen}) {
  Uint8List raw;
  try {
    raw = base64.decode(text);
  } on FormatException {
    throw const InvalidEncodingError('invalid base64 field');
  }
  if (expectLen != null && raw.length != expectLen) {
    throw InvalidEncodingError('field must decode to $expectLen bytes');
  }
  return raw;
}

/// Double Ratchet header: authenticated but not encrypted.
///
/// The relay can read these fields — the recipient needs them to select a
/// chain — but cannot modify them, because they are covered by AEAD associated
/// data.
class RatchetHeader {
  const RatchetHeader({
    required this.dhPub,
    required this.pn,
    required this.n,
    this.version = protocolVersion,
  });

  final Uint8List dhPub;
  final int pn;
  final int n;
  final int version;

  Uint8List encode() => concat(<List<int>>[
        u8(version),
        validateX25519Public(dhPub),
        u32(pn),
        u32(n),
      ]);

  static RatchetHeader decode(Uint8List data) {
    if (data.length != headerLen) {
      throw const InvalidEncodingError('header has wrong length');
    }
    final int version = data[0];
    if (version != protocolVersion) {
      throw InvalidEncodingError('unsupported protocol version $version');
    }
    final ByteData view = ByteData.sublistView(data);
    return RatchetHeader(
      dhPub: validateX25519Public(data.sublist(1, 1 + x25519KeyLen)),
      pn: view.getUint32(1 + x25519KeyLen),
      n: view.getUint32(1 + x25519KeyLen + 4),
      version: version,
    );
  }
}
