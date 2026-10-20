/// HELO 2.0 protocol conformance: hybrid PQXDH, padding, STREAM attachments.
///
/// Like vector_conformance_test.dart, these replay vectors produced by the
/// normative Python reference. The PQXDH group goes one step further than the
/// classical vectors: the ML-KEM key pair and ciphertext in the vector file
/// came from OpenSSL, so these tests check the Dart ML-KEM implementation
/// against OpenSSL's, byte for byte — not against itself.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:helo/crypto/attachment.dart';
import 'package:helo/crypto/encoding.dart';
import 'package:helo/crypto/envelope.dart';
import 'package:helo/crypto/errors.dart';
import 'package:helo/crypto/identity.dart';
import 'package:helo/crypto/padding.dart';
import 'package:helo/crypto/pq.dart';
import 'package:helo/crypto/pqxdh.dart';
import 'package:helo/crypto/prekeys.dart';
import 'package:helo/crypto/primitives.dart';
import 'package:helo/crypto/session.dart';
import 'package:helo/crypto/x3dh.dart';

late Map<String, dynamic> vectors;

Map<String, dynamic> _map(Object? v) => v! as Map<String, dynamic>;
List<Object?> _list(Object? v) => v! as List<Object?>;
String _str(Object? v) => v! as String;

Future<IdentityKeyPair> identityFrom(Map<String, dynamic> v) async {
  final KeyPairBytes sig = await ed25519FromSeed(b64d(_str(v['sig_seed'])));
  final KeyPairBytes dh = await x25519FromPrivate(b64d(_str(v['dh_priv'])));
  final Uint8List binding = await ed25519Sign(
    sig.privateKey,
    concat(<List<int>>[identityBindingContext, dh.publicKey]),
  );
  return IdentityKeyPair(
    sigSeed: sig.privateKey,
    sigPub: sig.publicKey,
    dhPriv: dh.privateKey,
    dhPub: dh.publicKey,
    bindingSig: binding,
  );
}

/// Bob's prekey store rebuilt from the pinned private material in the vector.
PreKeyStore bobStore(IdentityKeyPair bob, Map<String, dynamic> v) {
  final Map<String, dynamic> bundle = _map(v['bob_prekey_bundle']);
  final Map<String, dynamic> spk = _map(bundle['signed_prekey']);
  final Map<String, dynamic> otp = _map(bundle['one_time_prekey']);
  final Map<String, dynamic> pq = _map(bundle['pq_prekey']);
  return PreKeyStore.fromStorageJson(bob, <String, dynamic>{
    'v': 1,
    'current_signed_id': spk['key_id'],
    'next_signed_id': (spk['key_id']! as int) + 1,
    'next_one_time_id': (otp['key_id']! as int) + 1,
    'signed': <Object?>[
      <String, dynamic>{
        'key_id': spk['key_id'],
        'private': v['bob_signed_prekey_private'],
        'public': spk['public'],
        'created_at': spk['created_at'],
        'signature': spk['signature'],
      },
    ],
    'one_time': <Object?>[
      <String, dynamic>{
        'key_id': otp['key_id'],
        'private': v['bob_one_time_prekey_private'],
        'public': otp['public'],
        'created_at': 0,
      },
    ],
    'pq': <Object?>[
      <String, dynamic>{
        'key_id': pq['key_id'],
        'seed': v['bob_pq_prekey_seed'],
        'public': pq['public'],
        'signature': pq['signature'],
        'last_resort': false,
        'created_at': 0,
      },
    ],
    'current_pq_last_resort': null,
    'next_pq_id': (pq['key_id']! as int) + 1,
  });
}

class CountingKem implements Kem {
  int calls = 0;
  @override
  KemEncapsulation encapsulate(Uint8List ek) {
    calls += 1;
    return const MlKem768().encapsulate(ek);
  }
}

/// A Dart-only Bob with fresh keys, for round trips and attack tests.
Future<(IdentityKeyPair, PreKeyStore)> freshBob({bool withPq = true}) async {
  final IdentityKeyPair bob = await IdentityKeyPair.generate();
  final PreKeyStore store = PreKeyStore(bob);
  await store.rotateSignedPreKey();
  await store.generateOneTimePreKeys(2);
  if (withPq) {
    await store.rotatePqLastResort();
    await store.generatePqOneTimePreKeys(1);
  }
  return (bob, store);
}

PreKeyBundle bundleFor(IdentityKeyPair bob, PreKeyStore store,
    {OneTimePreKeyPublic? otp, PqPreKeyPublic? pq}) {
  return PreKeyBundle(
    deviceId: 'bob-device',
    identity: bob.public,
    signedPreKey: store.currentSignedPreKey,
    oneTimePreKey: otp,
    pqPreKey: pq,
  );
}

void main() {
  setUpAll(() {
    vectors = _map(jsonDecode(
        File('../tests/vectors/helo_vectors.json').readAsStringSync()));
  });

  group('PQXDH conformance (against the reference and OpenSSL)', () {
    test('info string matches the reference', () {
      expect(String.fromCharCodes(infoPqxdh), equals(_str(_map(vectors['pqxdh'])['info'])));
    });

    test('ML-KEM seeded keygen reproduces the OpenSSL public key', () {
      final Map<String, dynamic> v = _map(vectors['pqxdh']);
      final Uint8List seed = b64d(_str(v['bob_pq_prekey_seed']));
      final Uint8List published = b64d(_str(_map(_map(v['bob_prekey_bundle'])['pq_prekey'])['public']));
      expect(encodePqPublic(MlKem768.publicFromSeed(seed)), equals(published));
    });

    test('ML-KEM decapsulation reproduces the OpenSSL shared secret', () {
      final Map<String, dynamic> v = _map(vectors['pqxdh']);
      expect(
        MlKem768.decapsulate(
            b64d(_str(v['bob_pq_prekey_seed'])), b64d(_str(v['kem_ciphertext']))),
        equals(b64d(_str(v['kem_shared_secret']))),
      );
    });

    test('the reference hybrid bundle verifies, including the PQ signature', () async {
      final PreKeyBundle bundle =
          PreKeyBundle.fromJson(_map(_map(vectors['pqxdh'])['bob_prekey_bundle']));
      expect(bundle.pqPreKey, isNotNull);
      await bundle.verify();
    });

    test('responder derives the reference session key, AD and session id', () async {
      final Map<String, dynamic> v = _map(vectors['pqxdh']);
      final IdentityKeyPair bob = await identityFrom(_map(v['bob_identity_private']));
      final Envelope first = Envelope.fromJson(
          _map(_map(_list(v['transcript'])[0])['envelope']));
      final X3dhResult result = await pqxdhRespond(
          identity: bob, prekeys: bobStore(bob, v), header: first.x3dh!);
      expect(b64e(result.sharedSecret), equals(_str(v['shared_secret'])),
          reason: 'DH order, KEM secret placement or info string diverges');
      expect(b64e(result.associatedData), equals(_str(v['associated_data'])));
      expect(result.sessionId, equals(_str(v['session_id'])));
    });

    test('responder decrypts the reference hybrid first message', () async {
      final Map<String, dynamic> v = _map(vectors['pqxdh']);
      final IdentityKeyPair bob = await identityFrom(_map(v['bob_identity_private']));
      final Map<String, dynamic> entry = _map(_list(v['transcript'])[0]);
      final Envelope first = Envelope.fromJson(_map(entry['envelope']));
      final Session session = await startAsResponder(
        identity: bob,
        localDeviceId: 'bob-device-1',
        prekeys: bobStore(bob, v),
        envelope: first,
        acceptClassical: false,
      );
      expect(await session.decryptMessage(first), equals(b64d(_str(entry['plaintext']))));
      expect(session.kex, equals('pqxdh-mlkem768'));
    });
  });

  group('PQXDH behaviour and attacks (Dart ↔ Dart)', () {
    test('initiator and responder agree, and the conversation ratchets', () async {
      final (IdentityKeyPair bob, PreKeyStore store) = await freshBob();
      final IdentityKeyPair alice = await IdentityKeyPair.generate();
      final List<PqPreKeyPublic> pqs = await store.generatePqOneTimePreKeys(1);
      final Session a = await startAsInitiator(
        identity: alice,
        localDeviceId: 'alice-device',
        bundle: bundleFor(bob, store, pq: pqs.single),
        kex: const Pqxdh(),
      );
      final Envelope first =
          Envelope.fromJson((await a.encryptMessage(utf8.encode('hi'))).toJson());
      expect(first.x3dh!.isHybrid, isTrue);
      final Session b = await startAsResponder(
          identity: bob, localDeviceId: 'bob-device', prekeys: store,
          envelope: first, acceptClassical: false);
      expect(utf8.decode(await b.decryptMessage(first)), equals('hi'));
      final Envelope reply =
          Envelope.fromJson((await b.encryptMessage(utf8.encode('yo'))).toJson());
      expect(utf8.decode(await a.decryptMessage(reply)), equals('yo'));
      expect(a.kex, equals('pqxdh-mlkem768'));
    });

    test('a bundle without a PQ prekey is refused, not downgraded', () async {
      final (IdentityKeyPair bob, PreKeyStore store) = await freshBob(withPq: false);
      expect(
        startAsInitiator(
          identity: await IdentityKeyPair.generate(),
          localDeviceId: 'a',
          bundle: bundleFor(bob, store),
          kex: const Pqxdh(),
        ),
        throwsA(isA<PostQuantumUnavailableError>()),
      );
    });

    test('a substituted PQ key is rejected before any encapsulation', () async {
      final (IdentityKeyPair bob, PreKeyStore store) = await freshBob();
      final PqPreKeyPublic genuine = store.currentPqLastResort!;
      final (Uint8List _, Uint8List attackerEk) = MlKem768.generate();
      final PqPreKeyPublic forged = PqPreKeyPublic(
        keyId: genuine.keyId,
        encodedPublic: encodePqPublic(attackerEk),
        signature: genuine.signature,
        oneTime: false,
      );
      final CountingKem kem = CountingKem();
      await expectLater(
        pqxdhInitiate(
          identity: await IdentityKeyPair.generate(),
          bundle: bundleFor(bob, store, pq: forged),
          kem: kem,
        ),
        throwsA(isA<SignatureVerificationError>()),
      );
      expect(kem.calls, equals(0));
    });

    test('a tampered KEM ciphertext fails authentication', () async {
      final (IdentityKeyPair bob, PreKeyStore store) = await freshBob();
      final Session a = await startAsInitiator(
        identity: await IdentityKeyPair.generate(),
        localDeviceId: 'a',
        bundle: bundleFor(bob, store, pq: store.currentPqLastResort),
        kex: const Pqxdh(),
      );
      final Map<String, dynamic> obj =
          (await a.encryptMessage(utf8.encode('secret'))).toJson();
      final Map<String, dynamic> pq = _map(_map(obj['x3dh'])['pq']);
      final Uint8List ct = b64d(_str(pq['ct']));
      ct[10] ^= 1;
      pq['ct'] = b64e(ct);
      final Envelope env = Envelope.fromJson(obj);
      final Session b = await startAsResponder(
          identity: bob, localDeviceId: 'b', prekeys: store, envelope: env);
      await expectLater(b.decryptMessage(env), throwsA(isA<AuthenticationError>()));
    });

    test('a downgraded initial message is refused by the hybrid policy', () async {
      final (IdentityKeyPair bob, PreKeyStore store) = await freshBob();
      final Session a = await startAsInitiator(
        identity: await IdentityKeyPair.generate(),
        localDeviceId: 'a',
        bundle: bundleFor(bob, store, pq: store.currentPqLastResort),
        kex: const Pqxdh(),
      );
      final Map<String, dynamic> obj =
          (await a.encryptMessage(utf8.encode('x'))).toJson();
      final Map<String, dynamic> header = _map(obj['x3dh']);
      header.remove('pq');
      header['version'] = 1;
      final Envelope env = Envelope.fromJson(obj);
      await expectLater(
        startAsResponder(identity: bob, localDeviceId: 'b', prekeys: store,
            envelope: env, acceptClassical: false),
        throwsA(isA<DowngradeRejectedError>()),
      );
      // Even a permissive responder never opens it under the weaker key.
      final Session permissive = await startAsResponder(
          identity: bob, localDeviceId: 'b', prekeys: store, envelope: env);
      await expectLater(permissive.decryptMessage(env), throwsA(isA<AuthenticationError>()));
    });

    test('header version and PQ data must agree', () async {
      final Map<String, dynamic> obj = _map(jsonDecode(jsonEncode(
          _map(_list(_map(vectors['pqxdh'])['transcript'])[0])['envelope'])));
      final Map<String, dynamic> header = _map(obj['x3dh']);
      header['version'] = 1;
      expect(() => Envelope.fromJson(obj), throwsA(isA<InvalidEncodingError>()));
      header['version'] = 2;
      header.remove('pq');
      expect(() => Envelope.fromJson(obj), throwsA(isA<InvalidEncodingError>()));
    });

    test('PQ prekeys survive the storage round trip', () async {
      final (IdentityKeyPair bob, PreKeyStore store) = await freshBob();
      final PreKeyStore restored = PreKeyStore.fromStorageJson(
          bob, _map(jsonDecode(jsonEncode(store.toStorageJson()))));
      expect(restored.pqOneTimePreKeyCount, equals(store.pqOneTimePreKeyCount));
      expect(restored.currentPqLastResort!.encodedPublic,
          equals(store.currentPqLastResort!.encodedPublic));
    });
  });

  group('padding conformance', () {
    test('every policy pads to the reference length', () {
      for (final Object? raw in _list(_map(vectors['padding'])['cases'])) {
        final Map<String, dynamic> c = _map(raw);
        final PaddingPolicy policy = paddingPolicies[_str(c['policy'])]!;
        final int n = c['payload_length']! as int;
        expect(pad(Uint8List(n), policy).length, equals(c['padded_length']),
            reason: '${c['policy']} at $n bytes');
      }
    });

    test('the reference example pads byte-identically and round-trips', () {
      final Map<String, dynamic> ex = _map(_map(vectors['padding'])['example']);
      final Uint8List payload = b64d(_str(ex['payload']));
      expect(b64e(pad(payload)), equals(_str(ex['padded'])));
      expect(unpad(b64d(_str(ex['padded']))), equals(payload));
    });

    test('malformed padding is rejected', () {
      for (final List<int> bad in <List<int>>[
        <int>[],
        List<int>.filled(16, 0),
        <int>[1, 2, 3],
        <int>[1, 0x80, 0, 1],
      ]) {
        expect(() => unpad(bad), throwsA(isA<InvalidEncodingError>()));
      }
    });
  });

  group('attachment conformance', () {
    test('STREAM encryption is byte-identical to the reference', () async {
      final Map<String, dynamic> v = _map(vectors['attachment']);
      final Uint8List key = b64d(_str(v['key']));
      final Uint8List plain = b64d(_str(v['plaintext']));
      final int chunk = v['chunk_size']! as int;
      expect(b64e(await encryptAttachment(key, plain, chunk)), equals(_str(v['ciphertext'])));
      expect(
        b64e(await encryptAttachment(key, b64d(_str(v['default_chunk_plaintext'])))),
        equals(_str(v['default_chunk_ciphertext'])),
      );
    });

    test('decrypts the reference ciphertext and checks its digest', () async {
      final Map<String, dynamic> v = _map(vectors['attachment']);
      final Uint8List ct = b64d(_str(v['ciphertext']));
      await verifyAttachmentDigest(ct, b64d(_str(v['digest'])));
      expect(
        await decryptAttachment(b64d(_str(v['key'])), ct, v['chunk_size']! as int),
        equals(b64d(_str(v['plaintext']))),
      );
    });

    test('tampering, truncation and reordering are detected', () async {
      final Map<String, dynamic> v = _map(vectors['attachment']);
      final Uint8List key = b64d(_str(v['key']));
      final Uint8List ct = b64d(_str(v['ciphertext']));
      const int seg = 64 + 16;

      final Uint8List flipped = Uint8List.fromList(ct)..[5] ^= 1;
      final Uint8List truncated = Uint8List.sublistView(ct, 0, ct.length - 1);
      final Uint8List droppedLast = Uint8List.sublistView(ct, 0, 2 * seg);
      final Uint8List reordered = Uint8List.fromList(<int>[
        ...ct.sublist(seg, 2 * seg), ...ct.sublist(0, seg), ...ct.sublist(2 * seg),
      ]);
      for (final Uint8List bad in <Uint8List>[flipped, truncated, droppedLast, reordered]) {
        await expectLater(decryptAttachment(key, bad, 64),
            throwsA(isA<AuthenticationError>()));
      }
      await expectLater(verifyAttachmentDigest(flipped, b64d(_str(v['digest']))),
          throwsA(isA<AuthenticationError>()));
    });
  });
}
