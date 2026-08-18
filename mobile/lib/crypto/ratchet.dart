/// Double Ratchet — direct port of `helo_ref/ratchet.py`.
///
/// Two ratchets run simultaneously:
///
///   Symmetric-key ratchet   advances once per message; derives a unique
///                           message key and replaces the chain key. One-way.
///   DH ratchet              advances when the peer presents a new ratchet
///                           public key; mixes fresh DH output into the root
///                           key and derives new chains.
///
/// Bounds: [maxSkip] and [maxSkippedKeys] exist because message-key derivation
/// is attacker-triggerable. A header claiming n = 4_000_000_000 would otherwise
/// force four billion HMAC operations and unbounded memory.
///
/// Atomicity: [decrypt] works on a COPY of the state and returns the new state
/// only on success. A tampered or replayed ciphertext therefore cannot
/// desynchronise a live session — which would otherwise be a trivial
/// denial-of-service against any conversation an active attacker can reach.
library;

import 'dart:typed_data';

import 'encoding.dart';
import 'errors.dart';
import 'primitives.dart';

const int maxSkip = 1000;
const int maxSkippedKeys = 2000;
const int maxRememberedRatchetKeys = 20;

// --- KDFs -------------------------------------------------------------------

/// Root KDF. Returns (newRootKey, newChainKey).
///
/// The current root key is the HKDF salt and the DH output is the input keying
/// material, so the new root key depends on both the whole session history and
/// the fresh DH — which is what makes break-in recovery possible.
Future<(Uint8List, Uint8List)> kdfRoot(
  List<int> rootKey,
  List<int> dhOutput,
) async {
  final Uint8List out = await hkdf(
    ikm: dhOutput,
    salt: rootKey,
    info: infoRootRatchet,
    length: rootKeyLen + chainKeyLen,
  );
  return (out.sublist(0, rootKeyLen), out.sublist(rootKeyLen));
}

/// Symmetric ratchet step. Returns (messageKey, nextChainKey).
Future<(Uint8List, Uint8List)> kdfChain(List<int> chainKey) async {
  final Uint8List messageKey =
      await hmacSha256(chainKey, <int>[chainConstMessageKey]);
  final Uint8List nextChainKey =
      await hmacSha256(chainKey, <int>[chainConstNextChainKey]);
  return (messageKey, nextChainKey);
}

/// Expand a message key into (aesKey, nonce).
///
/// DELIBERATE DEVIATION from a randomly generated, transmitted nonce. AES-GCM
/// fails catastrophically on nonce reuse. With a random nonce that safety
/// depends on the sender's RNG being healthy at every send; with derivation it
/// depends only on each message key being used exactly once, which the ratchet
/// guarantees structurally. This turns a runtime assumption into a structural
/// one and removes 12 bytes per message from the wire.
Future<(Uint8List, Uint8List)> expandMessageKey(List<int> messageKey) async {
  final Uint8List out = await hkdf(
    ikm: messageKey,
    salt: zeroSalt,
    info: infoMessageKeys,
    length: aes256KeyLen + aesGcmNonceLen,
  );
  return (out.sublist(0, aes256KeyLen), out.sublist(aes256KeyLen));
}

// --- State ------------------------------------------------------------------

/// Key for the skipped-message store: (ratchet public key, counter).
class SkippedKeyId {
  SkippedKeyId(this.dhPub, this.n);
  final Uint8List dhPub;
  final int n;

  String get _key => '${b64e(dhPub)}|$n';

  @override
  bool operator ==(Object other) =>
      other is SkippedKeyId && other._key == _key;

  @override
  int get hashCode => _key.hashCode;
}

/// Complete Double Ratchet state.
///
/// Every field except [sessionVersion] is secret or security-relevant. This
/// object must never be logged and must only be persisted through the
/// encrypted-state path.
class RatchetState {
  RatchetState({
    required this.rootKey,
    required this.dhSendPriv,
    required this.dhSendPub,
    this.dhRecvPub,
    this.chainKeySend,
    this.chainKeyRecv,
    this.nSend = 0,
    this.nRecv = 0,
    this.prevChainLen = 0,
    Map<SkippedKeyId, Uint8List>? skipped,
    List<Uint8List>? seenRemoteRatchets,
    this.sessionVersion = 1,
  })  : skipped = skipped ?? <SkippedKeyId, Uint8List>{},
        seenRemoteRatchets = seenRemoteRatchets ?? <Uint8List>[];

  Uint8List rootKey;
  Uint8List dhSendPriv;
  Uint8List dhSendPub;
  Uint8List? dhRecvPub;
  Uint8List? chainKeySend;
  Uint8List? chainKeyRecv;
  int nSend;
  int nRecv;
  int prevChainLen;
  Map<SkippedKeyId, Uint8List> skipped;
  List<Uint8List> seenRemoteRatchets;
  int sessionVersion;

  RatchetState copy() => RatchetState(
        rootKey: Uint8List.fromList(rootKey),
        dhSendPriv: Uint8List.fromList(dhSendPriv),
        dhSendPub: Uint8List.fromList(dhSendPub),
        dhRecvPub: dhRecvPub == null ? null : Uint8List.fromList(dhRecvPub!),
        chainKeySend:
            chainKeySend == null ? null : Uint8List.fromList(chainKeySend!),
        chainKeyRecv:
            chainKeyRecv == null ? null : Uint8List.fromList(chainKeyRecv!),
        nSend: nSend,
        nRecv: nRecv,
        prevChainLen: prevChainLen,
        skipped: Map<SkippedKeyId, Uint8List>.from(skipped),
        seenRemoteRatchets:
            seenRemoteRatchets.map(Uint8List.fromList).toList(),
        sessionVersion: sessionVersion,
      );

  /// Structural invariants, enforced when loading persisted state.
  Future<void> validate() async {
    if (rootKey.length != rootKeyLen) {
      throw const SessionStateCorruptError('root key has wrong length');
    }
    if (dhSendPriv.length != x25519KeyLen ||
        dhSendPub.length != x25519KeyLen) {
      throw const SessionStateCorruptError('ratchet key has wrong length');
    }
    final KeyPairBytes derived = await x25519FromPrivate(dhSendPriv);
    if (!constantTimeEquals(derived.publicKey, dhSendPub)) {
      throw const SessionStateCorruptError('ratchet key pair is inconsistent');
    }
    if (nSend < 0 || nRecv < 0 || prevChainLen < 0) {
      throw const SessionStateCorruptError('negative counter in ratchet state');
    }
    if (skipped.length > maxSkippedKeys) {
      throw const SessionStateCorruptError('skipped-key store exceeds bound');
    }
  }
}

// --- Initialisation ---------------------------------------------------------

/// Alice. She can send immediately, before Bob is ever online.
Future<RatchetState> initInitiator({
  required Uint8List sharedSecret,
  required Uint8List remoteSignedPreKeyPub,
  RandomSource? rng,
}) async {
  if (sharedSecret.length != rootKeyLen) {
    throw const InvalidStateTransitionError('X3DH secret has wrong length');
  }
  final KeyPairBytes kp = await x25519Generate(rng);
  final Uint8List dhOut =
      await x25519Dh(kp.privateKey, remoteSignedPreKeyPub);
  final (Uint8List rk, Uint8List cks) = await kdfRoot(sharedSecret, dhOut);
  return RatchetState(
    rootKey: rk,
    dhSendPriv: kp.privateKey,
    dhSendPub: kp.publicKey,
    dhRecvPub: Uint8List.fromList(remoteSignedPreKeyPub),
    chainKeySend: cks,
  );
}

/// Bob. He has no sending chain until he receives Alice's first message.
Future<RatchetState> initResponder({
  required Uint8List sharedSecret,
  required Uint8List signedPreKeyPriv,
}) async {
  if (sharedSecret.length != rootKeyLen) {
    throw const InvalidStateTransitionError('X3DH secret has wrong length');
  }
  final KeyPairBytes kp = await x25519FromPrivate(signedPreKeyPriv);
  return RatchetState(
    rootKey: sharedSecret,
    dhSendPriv: kp.privateKey,
    dhSendPub: kp.publicKey,
  );
}

// --- Internal ---------------------------------------------------------------

void _rememberRemoteRatchet(RatchetState s, Uint8List dhPub) {
  for (final Uint8List seen in s.seenRemoteRatchets) {
    if (constantTimeEquals(seen, dhPub)) return;
  }
  s.seenRemoteRatchets.add(Uint8List.fromList(dhPub));
  if (s.seenRemoteRatchets.length > maxRememberedRatchetKeys) {
    s.seenRemoteRatchets.removeAt(0);
  }
}

Future<void> _dhRatchet(
  RatchetState s,
  RatchetHeader header,
  RandomSource? rng,
) async {
  s.prevChainLen = s.nSend;
  s.nSend = 0;
  s.nRecv = 0;
  if (s.dhRecvPub != null) _rememberRemoteRatchet(s, s.dhRecvPub!);
  s.dhRecvPub = Uint8List.fromList(header.dhPub);

  // First half-step: receiving chain from the peer's new key.
  final (Uint8List rk1, Uint8List ckr) =
      await kdfRoot(s.rootKey, await x25519Dh(s.dhSendPriv, s.dhRecvPub!));
  s.rootKey = rk1;
  s.chainKeyRecv = ckr;

  // Second half-step: fresh local ratchet key -> new sending chain.
  final KeyPairBytes kp = await x25519Generate(rng);
  s.dhSendPriv = kp.privateKey;
  s.dhSendPub = kp.publicKey;
  final (Uint8List rk2, Uint8List cks) =
      await kdfRoot(s.rootKey, await x25519Dh(s.dhSendPriv, s.dhRecvPub!));
  s.rootKey = rk2;
  s.chainKeySend = cks;
}

Future<void> _skipMessageKeys(RatchetState s, int until) async {
  if (s.chainKeyRecv == null) {
    if (until > 0) {
      throw const InvalidStateTransitionError(
          'cannot skip messages without a receiving chain');
    }
    return;
  }
  if (until - s.nRecv > maxSkip) {
    throw TooManySkippedMessagesError(
        'header claims ${until - s.nRecv} skipped messages; limit is $maxSkip');
  }
  while (s.nRecv < until) {
    final (Uint8List mk, Uint8List next) = await kdfChain(s.chainKeyRecv!);
    s.chainKeyRecv = next;
    if (s.skipped.length >= maxSkippedKeys) {
      throw const TooManySkippedMessagesError('skipped-key store is full');
    }
    s.skipped[SkippedKeyId(s.dhRecvPub!, s.nRecv)] = mk;
    s.nRecv += 1;
  }
}

// --- Encrypt / decrypt ------------------------------------------------------

class EncryptedMessage {
  const EncryptedMessage(this.header, this.ciphertext);
  final RatchetHeader header;
  final Uint8List ciphertext;
}

/// Encrypt one message, advancing the symmetric ratchet exactly one step.
Future<EncryptedMessage> encrypt(
  RatchetState s,
  List<int> plaintext,
  List<int> associatedData,
) async {
  if (s.chainKeySend == null) {
    throw const InvalidStateTransitionError(
        'no sending chain: this session cannot send until it has received');
  }
  final (Uint8List mk, Uint8List next) = await kdfChain(s.chainKeySend!);
  s.chainKeySend = next;

  final RatchetHeader header =
      RatchetHeader(dhPub: s.dhSendPub, pn: s.prevChainLen, n: s.nSend);
  s.nSend += 1;

  final (Uint8List aesKey, Uint8List nonce) = await expandMessageKey(mk);
  final Uint8List ciphertext = await aes256GcmEncrypt(
    key: aesKey,
    nonce: nonce,
    plaintext: plaintext,
    associatedData: concat(<List<int>>[associatedData, header.encode()]),
  );
  wipe(mk);
  wipe(aesKey);
  return EncryptedMessage(header, ciphertext);
}

class DecryptResult {
  const DecryptResult(this.state, this.plaintext);
  final RatchetState state;
  final Uint8List plaintext;
}

/// Decrypt one message.
///
/// The INPUT state is never mutated: on any failure the caller discards the
/// result and keeps the old state, so a hostile message cannot break a working
/// session.
Future<DecryptResult> decrypt(
  RatchetState state,
  RatchetHeader header,
  Uint8List ciphertext,
  List<int> associatedData, {
  RandomSource? rng,
}) async {
  final RatchetState s = state.copy();
  final Uint8List ad = concat(<List<int>>[associatedData, header.encode()]);

  // Case 1: a message key we already skipped and stored.
  final SkippedKeyId id = SkippedKeyId(header.dhPub, header.n);
  final Uint8List? stored = s.skipped[id];
  if (stored != null) {
    final (Uint8List aesKey, Uint8List nonce) = await expandMessageKey(stored);
    final Uint8List plaintext = await aes256GcmDecrypt(
      key: aesKey,
      nonce: nonce,
      ciphertextAndTag: ciphertext,
      associatedData: ad,
    );
    // Consume the key only after authentication succeeds; this is what makes a
    // second delivery of the same ciphertext a ReplayError.
    s.skipped.remove(id);
    return DecryptResult(s, plaintext);
  }

  // Replay classification: if the header names a superseded ratchet key or an
  // already-consumed counter, the message key no longer exists. That is by
  // design (forward secrecy), and it means this is a replay or a duplicate.
  for (final Uint8List seen in s.seenRemoteRatchets) {
    if (constantTimeEquals(seen, header.dhPub)) {
      throw const ReplayError(
          'message belongs to a superseded chain; its key is consumed');
    }
  }
  if (s.dhRecvPub != null &&
      constantTimeEquals(s.dhRecvPub!, header.dhPub) &&
      header.n < s.nRecv) {
    throw const ReplayError('message number already consumed in this chain');
  }

  // Case 2: new remote ratchet key -> DH ratchet step.
  if (s.dhRecvPub == null || !constantTimeEquals(s.dhRecvPub!, header.dhPub)) {
    await _skipMessageKeys(s, header.pn);
    await _dhRatchet(s, header, rng);
  }

  // Case 3: normal or forward-skipped message in the current chain.
  await _skipMessageKeys(s, header.n);
  if (s.chainKeyRecv == null) {
    throw const InvalidStateTransitionError('no receiving chain available');
  }
  final (Uint8List mk, Uint8List next) = await kdfChain(s.chainKeyRecv!);
  s.chainKeyRecv = next;
  s.nRecv += 1;

  final (Uint8List aesKey, Uint8List nonce) = await expandMessageKey(mk);
  final Uint8List plaintext = await aes256GcmDecrypt(
    key: aesKey,
    nonce: nonce,
    ciphertextAndTag: ciphertext,
    associatedData: ad,
  );
  wipe(mk);
  wipe(aesKey);
  return DecryptResult(s, plaintext);
}
