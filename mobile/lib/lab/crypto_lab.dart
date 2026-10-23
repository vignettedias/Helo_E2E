/// Crypto Lab: run the REAL protocol code against throwaway identities and
/// attack it, so the defences can be watched rather than described.
///
/// Every experiment builds fresh in-memory identities (nothing touches the
/// user's keys, storage or the relay), performs the real operation, and
/// reports what actually happened. An experiment whose defence does NOT hold
/// is reported as a failure, never dressed up as a success.
library;

import 'dart:convert';
import 'dart:typed_data';

import '../crypto/encoding.dart';
import '../crypto/envelope.dart';
import '../crypto/errors.dart';
import '../crypto/identity.dart';
import '../crypto/pq.dart';
import '../crypto/pqxdh.dart';
import '../crypto/prekeys.dart';
import '../crypto/session.dart';

/// One line of lab output. [kind]: 'step', 'data', 'ok' (defence held / step
/// succeeded) or 'fail' (unexpected outcome).
class LabLine {
  const LabLine(this.kind, this.text);
  final String kind;
  final String text;
}

class LabResult {
  const LabResult(this.passed, this.lines);
  final bool passed;
  final List<LabLine> lines;
}

class LabExperiment {
  const LabExperiment(this.id, this.title, this.blurb, this.run);
  final String id;
  final String title;
  final String blurb;
  final Future<LabResult> Function() run;
}

String _hex(List<int> b, [int n = 8]) =>
    b.take(n).map((int x) => x.toRadixString(16).padLeft(2, '0')).join();

Future<(IdentityKeyPair, PreKeyStore)> _bob({bool withPq = true}) async {
  final IdentityKeyPair bob = await IdentityKeyPair.generate();
  final PreKeyStore store = PreKeyStore(bob);
  await store.rotateSignedPreKey();
  await store.generateOneTimePreKeys(1);
  if (withPq) {
    await store.rotatePqLastResort();
    await store.generatePqOneTimePreKeys(1);
  }
  return (bob, store);
}

PreKeyBundle _bundle(IdentityKeyPair bob, PreKeyStore store, {PqPreKeyPublic? pq}) => PreKeyBundle(
      deviceId: 'device-2',
      identity: bob.public,
      signedPreKey: store.currentSignedPreKey,
      pqPreKey: pq,
    );

/// A fresh hybrid session pair plus Alice's first envelope (as JSON).
Future<(Session, Session, Map<String, dynamic>)> _pair(String firstText) async {
  final (IdentityKeyPair bob, PreKeyStore store) = await _bob();
  final IdentityKeyPair alice = await IdentityKeyPair.generate();
  final Session a = await startAsInitiator(
    identity: alice, localDeviceId: 'device-1',
    bundle: _bundle(bob, store, pq: store.currentPqLastResort), kex: const Pqxdh());
  final Map<String, dynamic> first = (await a.encryptMessage(utf8.encode(firstText))).toJson();
  final Session b = await startAsResponder(
      identity: bob, localDeviceId: 'device-2', prekeys: store,
      envelope: Envelope.fromJson(first), acceptClassical: false);
  await b.decryptMessage(Envelope.fromJson(first));
  return (a, b, first);
}

Map<String, dynamic> _copy(Map<String, dynamic> j) => jsonDecode(jsonEncode(j)) as Map<String, dynamic>;

/// Runs [attack]; the defence held if it throws [E].
Future<LabResult> _expectBlocked<E extends Object>(List<LabLine> lines, Future<void> Function() attack, String how) async {
  try {
    await attack();
    lines.add(const LabLine('fail', 'NOT BLOCKED — the attack was accepted. This is a bug.'));
    return LabResult(false, lines);
  } on E catch (e) {
    lines.add(LabLine('ok', 'BLOCKED: ${e.runtimeType} — $how'));
    return LabResult(true, lines);
  } on Object catch (e) {
    lines.add(LabLine('fail', 'Rejected, but by an unexpected error: ${e.runtimeType}'));
    return LabResult(false, lines);
  }
}

final List<LabExperiment> labExperiments = <LabExperiment>[
  LabExperiment('handshake', 'Hybrid handshake (PQXDH)',
      'Two fresh identities agree on a session key: four X25519 exchanges + one ML-KEM-768 encapsulation.',
      () async {
    final List<LabLine> l = <LabLine>[];
    final (IdentityKeyPair bob, PreKeyStore store) = await _bob();
    final IdentityKeyPair alice = await IdentityKeyPair.generate();
    l.add(LabLine('data', 'user 1 identity  ${_hex(await alice.public.fingerprint())}…'));
    l.add(LabLine('data', 'user 2 identity  ${_hex(await bob.public.fingerprint())}…'));
    final PqPreKeyPublic pq = store.currentPqLastResort!;
    l.add(LabLine('step', 'user 2 publishes: signed X25519 prekey #${store.currentSignedPreKey.keyId}, '
        'one-time prekey, ML-KEM-768 prekey #${pq.keyId} (${pq.encodedPublic.length} B, Ed25519-signed)'));
    final Stopwatch sw = Stopwatch()..start();
    final Session a = await startAsInitiator(
        identity: alice, localDeviceId: 'device-1', bundle: _bundle(bob, store, pq: pq), kex: const Pqxdh());
    final Map<String, dynamic> first = (await a.encryptMessage(utf8.encode('hello, quantum-safe world'))).toJson();
    final int initMs = sw.elapsedMilliseconds;
    final Envelope env = Envelope.fromJson(first);
    l.add(const LabLine('step', 'user 1 verifies every signature, then: DH1..DH3 (+DH4 skipped: no OTP in bundle) '
        '+ ML-KEM-768 encapsulate'));
    l.add(LabLine('data', 'KEM ciphertext ${env.x3dh!.pqCiphertext!.length} B · header v${env.x3dh!.version} · '
        'first envelope ${utf8.encode(jsonEncode(first)).length} B · $initMs ms'));
    sw.reset();
    final Session b = await startAsResponder(
        identity: bob, localDeviceId: 'device-2', prekeys: store, envelope: env, acceptClassical: false);
    final String text = utf8.decode(await b.decryptMessage(env));
    l.add(LabLine('step', 'user 2 decapsulates and recomputes the same key (${sw.elapsedMilliseconds} ms)'));
    l.add(LabLine('data', 'user 2 decrypted: "$text"'));
    final Envelope reply = Envelope.fromJson((await b.encryptMessage(utf8.encode('received'))).toJson());
    final String back = utf8.decode(await a.decryptMessage(reply));
    final bool ok = text == 'hello, quantum-safe world' && back == 'received' && a.kex == 'pqxdh-mlkem768';
    l.add(LabLine(ok ? 'ok' : 'fail',
        ok ? 'SESSION UP: ${a.kex}, both directions decrypt, ratchet running' : 'handshake did not complete'));
    return LabResult(ok, l);
  }),
  LabExperiment('tamper', 'Flip one bit in transit',
      'A relay changes a single bit of the ciphertext. AES-256-GCM authentication must reject it.', () async {
    final List<LabLine> l = <LabLine>[];
    final (Session a, Session b, _) = await _pair('setup');
    final Map<String, dynamic> j = (await a.encryptMessage(utf8.encode('transfer 10 to user 2'))).toJson();
    final Uint8List ct = b64d(j['ciphertext'] as String);
    l.add(LabLine('step', 'intercepted ${ct.length} B ciphertext: ${_hex(ct)}…'));
    ct[ct.length ~/ 2] ^= 0x01;
    j['ciphertext'] = b64e(ct);
    l.add(LabLine('step', 'flipped 1 bit at byte ${ct.length ~/ 2}, forwarded to user 2'));
    return _expectBlocked<AuthenticationError>(
        l, () => b.decryptMessage(Envelope.fromJson(j)), 'the GCM tag no longer matches; nothing is decrypted');
  }),
  LabExperiment('replay', 'Replay an old message',
      'A relay delivers the same envelope twice. The used message key must not open it again.', () async {
    final List<LabLine> l = <LabLine>[];
    final (Session a, Session b, _) = await _pair('setup');
    final Map<String, dynamic> j = (await a.encryptMessage(utf8.encode('approve request'))).toJson();
    final String once = utf8.decode(await b.decryptMessage(Envelope.fromJson(_copy(j))));
    l.add(LabLine('step', 'first delivery decrypts: "$once"'));
    l.add(const LabLine('step', 'relay re-sends the identical envelope'));
    return _expectBlocked<ReplayError>(
        l, () => b.decryptMessage(Envelope.fromJson(_copy(j))), 'that message key was consumed and deleted');
  }),
  LabExperiment('downgrade', 'Strip the post-quantum part',
      'An attacker removes the ML-KEM ciphertext to force a classical-only session.', () async {
    final List<LabLine> l = <LabLine>[];
    final (IdentityKeyPair bob, PreKeyStore store) = await _bob();
    final Session a = await startAsInitiator(
        identity: await IdentityKeyPair.generate(), localDeviceId: 'device-1',
        bundle: _bundle(bob, store, pq: store.currentPqLastResort), kex: const Pqxdh());
    final Map<String, dynamic> j = (await a.encryptMessage(utf8.encode('x'))).toJson();
    final Map<String, dynamic> h = j['x3dh'] as Map<String, dynamic>;
    h.remove('pq');
    h['version'] = 1;
    l.add(const LabLine('step', 'removed header.pq and relabelled the header as classical v1'));
    return _expectBlocked<DowngradeRejectedError>(
        l,
        () => startAsResponder(identity: bob, localDeviceId: 'device-2', prekeys: store,
            envelope: Envelope.fromJson(j), acceptClassical: false),
        'the responder requires the hybrid handshake; no silent fallback');
  }),
  LabExperiment('nopq', 'Relay hides the PQ prekey',
      'A malicious relay serves a bundle without the ML-KEM key, hoping the sender falls back.', () async {
    final List<LabLine> l = <LabLine>[];
    final (IdentityKeyPair bob, PreKeyStore store) = await _bob(withPq: false);
    l.add(const LabLine('step', 'bundle served with pq_prekey = null (as a hostile relay would)'));
    return _expectBlocked<PostQuantumUnavailableError>(
        l,
        () async => startAsInitiator(identity: await IdentityKeyPair.generate(), localDeviceId: 'device-1',
            bundle: _bundle(bob, store), kex: const Pqxdh()),
        'the sender refuses to start a weaker session');
  }),
  LabExperiment('substitute', 'Swap in an attacker\'s KEM key',
      'The relay replaces bob\'s ML-KEM key with its own, keeping bob\'s old signature.', () async {
    final List<LabLine> l = <LabLine>[];
    final (IdentityKeyPair bob, PreKeyStore store) = await _bob();
    final PqPreKeyPublic genuine = store.currentPqLastResort!;
    final (Uint8List _, Uint8List attackerEk) = MlKem768.generate();
    final PqPreKeyPublic forged = PqPreKeyPublic(
        keyId: genuine.keyId, encodedPublic: encodePqPublic(attackerEk), signature: genuine.signature,
        oneTime: false);
    l.add(LabLine('step', 'replaced the KEM key ${_hex(genuine.encodedPublic, 6)}… with ${_hex(forged.encodedPublic, 6)}…'));
    return _expectBlocked<SignatureVerificationError>(
        l,
        () async => startAsInitiator(identity: await IdentityKeyPair.generate(), localDeviceId: 'device-1',
            bundle: _bundle(bob, store, pq: forged), kex: const Pqxdh()),
        'bob\'s Ed25519 signature does not cover the forged key; checked before any encapsulation');
  }),
];
