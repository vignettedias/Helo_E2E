/// Messenger behaviour, end to end, against the REAL relay process.
///
/// Every test starts its own relay (backend/src/server.js) with a fresh
/// database and drives two or three real clients through it over HTTP. The
/// properties tested here are the ones the domain layer exists to guarantee:
/// confidentiality is end to end, receivers enforce authorisation, ratchet
/// state is never rolled back, and failures are visible rather than silent.
@Timeout(Duration(seconds: 90))
library;

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:helo/crypto/encoding.dart';
import 'package:helo/crypto/envelope.dart';
import 'package:helo/crypto/errors.dart';
import 'package:helo/crypto/identity.dart';
import 'package:helo/crypto/padding.dart';
import 'package:helo/crypto/pqxdh.dart';
import 'package:helo/crypto/prekeys.dart';
import 'package:helo/crypto/primitives.dart';
import 'package:helo/crypto/session.dart';
import 'package:helo/data/relay_client.dart';
import 'package:helo/domain/messenger.dart';
import 'package:helo/domain/models.dart';
import 'package:helo/protocol/payload.dart';
import 'package:helo/storage/crypto_storage.dart';

import 'support/relay_harness.dart';

late RelayHarness relay;

Future<void> syncAll(List<Messenger> clients, {int rounds = 2}) async {
  for (int r = 0; r < rounds; r++) {
    for (final Messenger m in clients) {
      await m.sync();
    }
  }
}

List<String> bodies(Messenger m, String convId) => m.conversations[convId]!.messages
    .where((ChatMessage x) => !x.system)
    .map((ChatMessage x) => x.body)
    .toList();

void main() {
  setUp(() async => relay = await RelayHarness.start());
  tearDown(() async => relay.dispose());

  // ------------------------------------------------------------ basics

  test('two users exchange messages over a hybrid PQXDH session', () async {
    final (Messenger alice, _) = await relay.user('alice');
    final (Messenger bob, _) = await relay.user('bob');

    final Conversation a2b = await alice.openDirect('bob');
    await alice.sendText(a2b.id, 'hello bob');
    await bob.sync();
    expect(bodies(bob, 'd:alice'), <String>['hello bob']);

    await bob.sendText('d:alice', 'hi alice');
    await alice.sync();
    expect(bodies(alice, a2b.id), <String>['hello bob', 'hi alice']);

    // Both sides' sessions came from the hybrid handshake.
    expect(alice.sessionWith(bob.deviceId)!.kex, 'pqxdh-mlkem768');
    expect(bob.sessionWith(alice.deviceId)!.kex, 'pqxdh-mlkem768');
    expect(alice.keyEstablishmentOf(a2b), <String>{'pqxdh-mlkem768'});
  });

  test('status goes sent → delivered → read, and only via E2EE receipts', () async {
    final (Messenger alice, _) = await relay.user('alice');
    final (Messenger bob, _) = await relay.user('bob');
    final Conversation c = await alice.openDirect('bob');
    final ChatMessage m = await alice.sendText(c.id, 'status check');
    expect(m.status, MessageStatus.sent, reason: 'relay accepted it; nothing more is known');

    await bob.sync(); // decrypts and sends a delivered receipt
    await alice.sync();
    expect(m.status, MessageStatus.delivered);

    await bob.markRead('d:alice');
    await alice.sync();
    expect(m.status, MessageStatus.read);
  });

  test('read receipts are not sent when the reader disabled them', () async {
    final (Messenger alice, _) = await relay.user('alice');
    final (Messenger bob, _) = await relay.user('bob');
    await bob.updateSettings((AppSettings s) => s.readReceipts = false);
    final ChatMessage m = await alice.sendText((await alice.openDirect('bob')).id, 'x');
    await bob.sync();
    await bob.markRead('d:alice');
    await alice.sync();
    expect(m.status, MessageStatus.delivered, reason: 'delivered, but never read');
  });

  test('an unknown username is reported clearly', () async {
    final (Messenger alice, _) = await relay.user('alice');
    expect(() => alice.openDirect('nobody-here'), throwsA(isA<MessengerException>()));
    expect(() => alice.openDirect('alice'), throwsA(isA<MessengerException>()));
  });

  // ---------------------------------------- persistence & reliability

  test('the stored device id is the device id, not a bearer token', () async {
    final (Messenger alice, CryptoStorage store) = await relay.user('alice');
    expect(utf8.decode((await store.get(StorageKeys.deviceId))!), alice.deviceId);
    expect(alice.deviceId, startsWith('device-'));
  });

  test('identity, sessions, prekeys and history survive restarts on both sides', () async {
    final (Messenger alice0, CryptoStorage aStore) = await relay.user('alice');
    final (Messenger bob0, CryptoStorage bStore) = await relay.user('bob');
    await alice0.openDirect('bob');
    await alice0.dispose();

    // Alice restarts before sending: the pending hybrid header must survive.
    final Messenger alice1 = await relay.reopen(aStore);
    expect(alice1.identity.public.encode(), equals(alice0.identity.public.encode()));
    await alice1.sendText('d:bob', 'after a restart');
    await bob0.dispose();

    // Bob restarts before receiving: the one-time EC and PQ prekeys Alice
    // consumed must still be on his device.
    final Messenger bob1 = await relay.reopen(bStore);
    await bob1.sync();
    expect(bodies(bob1, 'd:alice'), <String>['after a restart']);
    await bob1.sendText('d:alice', 'got it');
    await alice1.sync();
    await alice1.dispose();
    await bob1.dispose();

    final Messenger alice2 = await relay.reopen(aStore);
    final Messenger bob2 = await relay.reopen(bStore);
    expect(bodies(alice2, 'd:bob'), <String>['after a restart', 'got it']);
    await alice2.sendText('d:bob', 'still ratcheting');
    await bob2.sync();
    expect(bodies(bob2, 'd:alice').last, 'still ratcheting');
    expect(bob2.contacts.containsKey('alice'), isTrue);
  });

  test('expired relay tokens are renewed transparently', () async {
    final (Messenger alice, _) = await relay.user('alice');
    final (Messenger bob, _) = await relay.user('bob');
    await alice.sendText((await alice.openDirect('bob')).id, 'before expiry');
    await bob.sync();

    // Both of Bob's tokens stop working server-side, as after an hour.
    await relay.revokeToken(bob.relay.accountToken!);
    await relay.revokeToken(bob.relay.deviceToken!);
    await alice.sendText('d:bob', 'after expiry');
    await bob.sync();
    expect(bodies(bob, 'd:alice'), <String>['before expiry', 'after expiry']);
  });

  test('a relay outage queues ciphertext and re-sends the SAME envelope after restart',
      () async {
    final (Messenger alice0, CryptoStorage aStore) = await relay.user('alice');
    final (Messenger bob, _) = await relay.user('bob');
    await alice0.sendText((await alice0.openDirect('bob')).id, 'one');
    await bob.sync();
    await alice0.sync();

    await relay.pause();
    final ChatMessage queued = await alice0.sendText('d:bob', 'sent during the outage');
    expect(queued.status, MessageStatus.pending);
    expect(alice0.pendingEnvelopes, 1);
    await alice0.dispose();

    // Alice's app restarts during the outage; the outbox is persisted.
    final Messenger alice1 = await relay.reopen(aStore);
    expect(alice1.pendingEnvelopes, 1);
    await relay.resume();
    await alice1.retryOutbox();
    expect(alice1.pendingEnvelopes, 0);
    await alice1.sendText('d:bob', 'after recovery');

    await bob.sync();
    // If the restart had rolled the ratchet back, "after recovery" would reuse
    // the outage message's key and Bob would reject one as a replay.
    expect(bodies(bob, 'd:alice'), <String>['one', 'sent during the outage', 'after recovery']);
  });

  test('concurrent sends and receives never roll a ratchet back', () async {
    final (Messenger alice, _) = await relay.user('alice');
    final (Messenger bob, _) = await relay.user('bob');
    await alice.sendText((await alice.openDirect('bob')).id, 'start');
    await bob.sync();
    await bob.sendText('d:alice', 'reply');

    // Alice decrypts Bob's reply while five sends are in flight.
    await Future.wait<Object?>(<Future<Object?>>[
      alice.sync(),
      for (int i = 0; i < 5; i++) alice.sendText('d:bob', 'burst $i'),
    ]);
    await bob.sync();
    final List<String> got = bodies(bob, 'd:alice');
    for (int i = 0; i < 5; i++) {
      expect(got, contains('burst $i'), reason: 'a reused message key would be rejected');
    }
  });

  test('simultaneous first messages from both sides converge', () async {
    final (Messenger alice, _) = await relay.user('alice');
    final (Messenger bob, _) = await relay.user('bob');
    await alice.sendText((await alice.openDirect('bob')).id, 'alice first');
    await bob.sendText((await bob.openDirect('alice')).id, 'bob first');
    await syncAll(<Messenger>[alice, bob]);
    for (int i = 0; i < 3; i++) {
      await alice.sendText('d:bob', 'a$i');
      await bob.sendText('d:alice', 'b$i');
      await syncAll(<Messenger>[alice, bob]);
    }
    expect(bodies(bob, 'd:alice'), containsAll(<String>['alice first', 'a0', 'a1', 'a2']));
    expect(bodies(alice, 'd:bob'), containsAll(<String>['bob first', 'b0', 'b1', 'b2']));
  });

  test('a tampered first message does not plant a conversation', () async {
    final (Messenger mallory, _) = await relay.user('mallory');
    final (Messenger bob, _) = await relay.user('bob');

    final FetchedBundle fb = await mallory.relay.fetchBundle(bob.deviceId);
    final Session s = await startAsInitiator(
        identity: mallory.identity, localDeviceId: mallory.deviceId,
        bundle: fb.bundle, kex: const Pqxdh());
    final Uint8List plain = AppPayload(
      id: mallory.freshId(), timestampMs: 0, kind: PayloadKind.msg,
      conv: const ConvRef.direct(), body: 'forged').encode();
    final Map<String, dynamic> env = (await s.encryptMessage(plain)).toJson();
    final Uint8List ct = b64d(env['ciphertext']! as String);
    ct[0] ^= 1;
    env['ciphertext'] = b64e(ct);
    await mallory.relay.sendBatch(<(String, Envelope)>[(bob.deviceId, Envelope.fromJson(env))]);

    await bob.sync();
    expect(bob.conversations, isEmpty,
        reason: 'a session is adopted only after its first message authenticates');
    await bob.sync(); // acknowledged, not retried forever
    expect(bob.conversations, isEmpty);
  });

  test('reset destroys local state and notifies the app', () async {
    final (Messenger alice, CryptoStorage store) = await relay.user('alice');
    bool notified = false;
    alice.onReset = () => notified = true;
    await alice.resetEverything();
    expect(notified, isTrue);
    expect(await store.containsKey(StorageKeys.identitySigSeed), isFalse);
    expect(await Messenger.restore(storage: store, relay: relay.client()), isNull);
  });

  // ------------------------------------------------------ messaging UX

  test('replies, reactions and forwarding round-trip', () async {
    final (Messenger alice, _) = await relay.user('alice');
    final (Messenger bob, _) = await relay.user('bob');
    final ChatMessage q = await alice.sendText((await alice.openDirect('bob')).id, 'question?');
    await bob.sync();
    await bob.sendText('d:alice', 'answer', replyToId: q.id);
    await bob.react('d:alice', q.id, '👍');
    await alice.sync();

    final ChatMessage answer = alice.conversations['d:bob']!.messages.last;
    expect(answer.reply!.id, q.id);
    expect(answer.reply!.snippet, 'question?');
    expect(q.reactions['bob'], '👍');

    await bob.react('d:alice', q.id, '👍'); // same emoji again removes it
    await alice.sync();
    expect(q.reactions.containsKey('bob'), isFalse);
  });

  test('edits and deletions apply, and only the author can make them', () async {
    final (Messenger alice, _) = await relay.user('alice');
    final (Messenger bob, _) = await relay.user('bob');
    final ChatMessage m = await alice.sendText((await alice.openDirect('bob')).id, 'tyop');
    await bob.sync();

    await alice.edit('d:bob', m.id, 'typo');
    await bob.sync();
    final ChatMessage atBob = bob.conversations['d:alice']!.byId(m.id)!;
    expect(atBob.body, 'typo');
    expect(atBob.edited, isTrue);

    // Bob, maliciously, edits and deletes Alice's message. Alice's client
    // must refuse both: authority is the authenticated sender, not the UI.
    await bob.sendRawPayload('d:alice', AppPayload(
        id: bob.freshId(), timestampMs: 0, kind: PayloadKind.edit,
        conv: const ConvRef.direct(), target: m.id, body: 'bob was here'));
    await bob.sendRawPayload('d:alice', AppPayload(
        id: bob.freshId(), timestampMs: 0, kind: PayloadKind.del,
        conv: const ConvRef.direct(), target: m.id));
    await alice.sync();
    expect(m.body, 'typo');
    expect(m.deleted, isFalse);

    await alice.deleteForEveryone('d:bob', m.id);
    await bob.sync();
    expect(atBob.deleted, isTrue);
    expect(atBob.body, isEmpty);
  });

  test('a payload delivered twice (fresh envelopes, same id) is shown once', () async {
    final (Messenger alice, _) = await relay.user('alice');
    final (Messenger bob, _) = await relay.user('bob');
    await alice.sendText((await alice.openDirect('bob')).id, 'hello');
    await bob.sync();

    // Each send is a NEW ratchet step, so the protocol's replay protection does
    // not apply; only the application-level payload id can catch this.
    final AppPayload dup = AppPayload(
        id: alice.freshId(), timestampMs: DateTime.now().millisecondsSinceEpoch,
        kind: PayloadKind.msg, conv: const ConvRef.direct(), body: 'only once');
    await alice.sendRawPayload('d:bob', dup);
    await alice.sendRawPayload('d:bob', dup);
    await bob.sync();
    expect(bodies(bob, 'd:alice'), <String>['hello', 'only once']);
  });

  test('typing indicators propagate, and are not sent when disabled', () async {
    final (Messenger alice, _) = await relay.user('alice');
    final (Messenger bob, _) = await relay.user('bob');
    await alice.sendText((await alice.openDirect('bob')).id, 'hi');
    await bob.sync();

    await alice.setTyping('d:bob', true);
    await bob.sync();
    expect(bob.typingIn('d:alice'), <String>['alice']);

    await alice.setTyping('d:bob', false);
    await bob.sync();
    expect(bob.typingIn('d:alice'), isEmpty);

    await alice.updateSettings((AppSettings s) => s.typingIndicators = false);
    await alice.setTyping('d:bob', true);
    await bob.sync();
    expect(bob.typingIn('d:alice'), isEmpty);
  });

  test('disappearing messages are removed on both sides after the timer', () async {
    final (Messenger alice, _) = await relay.user('alice');
    final (Messenger bob, _) = await relay.user('bob');
    final Conversation c = await alice.openDirect('bob');
    await alice.sendText(c.id, 'stays');
    await alice.setDisappearing(c.id, 1);
    await alice.sendText(c.id, 'vanishes');
    await bob.sync();
    expect(bob.conversations['d:alice']!.disappearingSeconds, 1);
    expect(bodies(bob, 'd:alice'), contains('vanishes'));

    await Future<void>.delayed(const Duration(milliseconds: 1300));
    await syncAll(<Messenger>[alice, bob], rounds: 1);
    expect(bodies(alice, c.id), <String>['stays']);
    expect(bodies(bob, 'd:alice'), <String>['stays']);
  });

  test('search finds messages across conversations', () async {
    final (Messenger alice, _) = await relay.user('alice');
    await relay.user('bob');
    final Conversation c = await alice.openDirect('bob');
    await alice.sendText(c.id, 'the quick brown fox');
    await alice.sendText(c.id, 'lazy dog');
    expect(alice.search('BROWN').map((SearchHit h) => h.message.body), <String>['the quick brown fox']);
    expect(alice.search('cat'), isEmpty);
  });

  test('blocking is enforced by the relay and is invisible to the sender', () async {
    final (Messenger alice, _) = await relay.user('alice');
    final (Messenger bob, _) = await relay.user('bob');
    await alice.sendText((await alice.openDirect('bob')).id, 'before');
    await bob.sync();
    await bob.block('alice');

    final ChatMessage m = await alice.sendText('d:bob', 'while blocked');
    expect(m.status, MessageStatus.sent, reason: 'the sender cannot tell');
    await bob.sync();
    expect(bodies(bob, 'd:alice'), <String>['before']);

    await bob.unblock('alice');
    await alice.sendText('d:bob', 'after');
    await bob.sync();
    expect(bodies(bob, 'd:alice'), <String>['before', 'after']);
  });

  test('pinning, archiving and muting order the list, silence notices, and persist', () async {
    final (Messenger alice, CryptoStorage aStore) = await relay.user('alice');
    final (Messenger bob, _) = await relay.user('bob');
    final (Messenger carol, _) = await relay.user('carol');
    await alice.sendText((await alice.openDirect('bob')).id, 'to bob');
    await alice.sendText((await alice.openDirect('carol')).id, 'to carol');

    List<String> ids({bool archived = false}) =>
        alice.sortedConversations(archived: archived).map((Conversation c) => c.id).toList();

    alice.setPinned('d:bob', true);
    expect(ids().first, 'd:bob', reason: 'pinned conversations sort first');
    alice.setArchived('d:carol', true);
    expect(ids(), <String>['d:bob']);
    expect(ids(archived: true), <String>['d:carol']);

    alice.setMuted('d:bob', true);
    final List<String> notified = <String>[];
    final StreamSubscription<IncomingNotice> sub =
        alice.incoming.listen((IncomingNotice n) => notified.add(n.conversation.id));
    await bob.sendText((await bob.openDirect('alice')).id, 'muted chat');
    await carol.sendText((await carol.openDirect('alice')).id, 'loud chat');
    await alice.sync();
    await Future<void>.delayed(Duration.zero);
    await sub.cancel();
    expect(notified, <String>['d:carol'], reason: 'a muted chat never notifies');
    expect(bodies(alice, 'd:bob'), contains('muted chat'), reason: 'muting does not drop messages');

    await alice.flush();
    final Messenger again = await relay.reopen(aStore);
    expect(again.conversations['d:bob']!.pinned, isTrue);
    expect(again.conversations['d:bob']!.muted, isTrue);
    expect(again.conversations['d:carol']!.archived, isTrue);
  });

  // --------------------------------------------------------- attachments

  test('attachments are encrypted on the device and only recipients can fetch them',
      () async {
    final (Messenger alice, _) = await relay.user('alice');
    final (Messenger bob, _) = await relay.user('bob');
    final (Messenger carol, _) = await relay.user('carol');
    final Uint8List file = Uint8List.fromList(List<int>.generate(150000, (int i) => i % 251));

    final ChatMessage sent = await alice.sendAttachment(
        (await alice.openDirect('bob')).id, file, name: 'data.bin', mime: 'application/octet-stream',
        caption: 'the file');
    await bob.sync();
    final ChatMessage got = bob.conversations['d:alice']!.messages.last;
    expect(got.body, 'the file');
    expect(got.attachments.single.name, 'data.bin');
    expect(await bob.loadAttachment(got.attachments.single), equals(file));

    // The relay serves the ciphertext only to listed devices.
    await expectLater(carol.relay.downloadAttachment(sent.attachments.single.id),
        throwsA(isA<RelayException>().having((RelayException e) => e.statusCode, 'status', 404)));
    // And what it stores is not the file.
    final Uint8List blob = await bob.relay.downloadAttachment(sent.attachments.single.id);
    expect(blob.length, greaterThan(file.length));
    expect(blob.sublist(0, 64), isNot(equals(file.sublist(0, 64))));
  });

  test('an attachment sent without a caption is delivered (regression: it was silently dropped)',
      () async {
    final (Messenger alice, _) = await relay.user('alice');
    final (Messenger bob, _) = await relay.user('bob');
    final Uint8List photo = Uint8List.fromList(List<int>.generate(2048, (int i) => i % 256));
    await alice.sendAttachment((await alice.openDirect('bob')).id, photo,
        name: 'photo.png', mime: 'image/png');
    await bob.sync();
    final ChatMessage got = bob.conversations['d:alice']!.messages.last;
    expect(got.body, isEmpty);
    expect(await bob.loadAttachment(got.attachments.single), equals(photo));
  });

  test('voice messages travel as encrypted audio attachments and stay voice when forwarded', () async {
    final (Messenger alice, _) = await relay.user('alice');
    final (Messenger bob, _) = await relay.user('bob');
    final (Messenger carol, _) = await relay.user('carol');
    // A real (tiny) WAV: 0.1 s of 16 kHz mono silence.
    final Uint8List wav = Uint8List.fromList(<int>[
      ...ascii.encode('RIFF'), 0x44, 0x0c, 0, 0, ...ascii.encode('WAVEfmt '), 16, 0, 0, 0, 1, 0, 1, 0,
      0x80, 0x3e, 0, 0, 0, 0x7d, 0, 0, 2, 0, 16, 0, ...ascii.encode('data'), 0x20, 0x0c, 0, 0,
      ...List<int>.filled(3200, 0),
    ]);

    expect(() => alice.sendAttachment('d:bob', wav, name: 'x.bin', mime: 'application/zip', voice: true),
        throwsA(isA<MessengerException>()));

    await alice.sendAttachment((await alice.openDirect('bob')).id, wav,
        name: 'voice.wav', mime: 'audio/wav', voice: true, durationMs: 100);
    await bob.sync();
    final AttachmentRef got = bob.conversations['d:alice']!.messages.last.attachments.single;
    expect(got.voice, isTrue);
    expect(got.durationMs, 100);
    expect(got.mime, 'audio/wav');
    expect(await bob.loadAttachment(got), equals(wav));

    // Forwarding re-encrypts under a fresh key and keeps it a voice note.
    final ChatMessage original = bob.conversations['d:alice']!.messages.last;
    await bob.openDirect('carol');
    await bob.forward('d:alice', original.id, 'd:carol');
    await carol.sync();
    final AttachmentRef fwd = carol.conversations['d:bob']!.messages.last.attachments.single;
    expect(fwd.voice, isTrue);
    expect(fwd.key, isNot(equals(got.key)));
    expect(await carol.loadAttachment(fwd), equals(wav));
  });

  test('attachment metadata is validated: voice must be audio, durations are bounded', () {
    Map<String, Object?> att(Map<String, Object?> extra) => <String, Object?>{
          'id': '0123456789abcdef0123456789abcdef', 'key': b64e(Uint8List(32)),
          'digest': b64e(Uint8List(32)), 'size': 10, 'mime': 'audio/wav', 'name': 'v.wav',
          'chunk': 65536, ...extra,
        };
    expect(AttachmentRef.fromJson(att(<String, Object?>{})).voice, isFalse,
        reason: 'older clients send no voice field');
    final AttachmentRef v = AttachmentRef.fromJson(att(<String, Object?>{'voice': true, 'dur': 4200}));
    expect(v.voice, isTrue);
    expect(v.durationMs, 4200);
    expect(AttachmentRef.fromJson(v.toJson()).durationMs, 4200);
    for (final Map<String, Object?> bad in <Map<String, Object?>>[
      <String, Object?>{'voice': 'yes'},
      <String, Object?>{'voice': false},
      <String, Object?>{'dur': -1},
      <String, Object?>{'dur': 1.5},
      <String, Object?>{'dur': AttachmentRef.maxVoiceMs + 1},
      <String, Object?>{'voice': true, 'mime': 'application/pdf'},
    ]) {
      expect(() => AttachmentRef.fromJson(att(bad)), throwsA(isA<InvalidEncodingError>()), reason: '$bad');
    }
  });

  // -------------------------------------------------------------- groups

  test('group messages fan out to every member', () async {
    final (Messenger alice, _) = await relay.user('alice');
    final (Messenger bob, _) = await relay.user('bob');
    final (Messenger carol, _) = await relay.user('carol');
    final Conversation g = await alice.createGroup('Trio', <String>['bob', 'carol']);
    await alice.sendText(g.id, 'hello group');
    await syncAll(<Messenger>[bob, carol], rounds: 1);
    expect(bodies(bob, g.id), <String>['hello group']);
    expect(bodies(carol, g.id), <String>['hello group']);

    await bob.sendText(g.id, 'hi from bob');
    await syncAll(<Messenger>[alice, carol], rounds: 1);
    expect(bodies(alice, g.id).last, 'hi from bob');
    expect(bodies(carol, g.id).last, 'hi from bob');
  });

  test('an invite link lets someone join; guessed and revoked links do not', () async {
    final (Messenger alice, _) = await relay.user('alice');
    final (Messenger bob, _) = await relay.user('bob');
    final (Messenger carol, _) = await relay.user('carol');
    final Conversation g = await alice.createGroup('Lab', <String>['bob']);
    await bob.sync();

    // Only admins can make links.
    expect(() => bob.createInviteLink(g.id), throwsA(isA<MessengerException>()));

    final String link = alice.createInviteLink(g.id);
    final ParsedInvite inv = ParsedInvite.parse(link)!;
    expect(inv.admin, 'alice');

    // A guessed secret is refused.
    await carol.requestJoinByInvite(inviteLinkText(inv.gid, 'alice', '0' * 32));
    await alice.sync();
    expect(alice.conversations[g.id]!.group!.members, isNot(contains('carol')));

    // The real link works: Carol is added and then receives group messages.
    expect(await carol.requestJoinByInvite(link), 'alice');
    await alice.sync();
    await syncAll(<Messenger>[carol, bob]);
    expect(alice.conversations[g.id]!.group!.members, contains('carol'));
    expect(carol.conversations[g.id], isNotNull);
    await alice.sendText(g.id, 'welcome carol');
    await carol.sync();
    expect(bodies(carol, g.id), contains('welcome carol'));
    expect(alice.conversations[g.id]!.group!.toSnapshot().toJson().toString(), isNot(contains(inv.secret)),
        reason: 'the secret never enters the shared group state');

    // Revoked: after removal, the old link no longer gets Carol back in.
    await alice.removeMember(g.id, 'carol');
    await carol.sync();
    alice.revokeInviteLinks(g.id);
    await carol.requestJoinByInvite(link);
    await alice.sync();
    expect(alice.conversations[g.id]!.group!.members, isNot(contains('carol')));
  });

  test('invite links are parsed strictly', () {
    const String gid = '0123456789abcdef0123456789abcdef';
    const String sec = 'fedcba9876543210fedcba9876543210';
    expect(ParsedInvite.parse(inviteLinkText(gid, 'alice', sec))!.secret, sec);
    for (final String bad in <String>[
      '', 'helo:invite:v1:', 'helo:invite:v2:$gid:alice:$sec', 'helo:invite:v1:$gid:alice',
      'helo:invite:v1:$gid:alice:$sec:x', 'helo:invite:v1:${gid.toUpperCase()}:alice:$sec',
      'helo:invite:v1:$gid:Al ice:$sec', 'helo:invite:v1:$gid:alice:${sec}00',
    ]) {
      expect(ParsedInvite.parse(bad), isNull, reason: bad);
    }
  });

  test('a non-admin cannot change the group, even by forging the message', () async {
    final (Messenger alice, _) = await relay.user('alice');
    final (Messenger bob, _) = await relay.user('bob');
    final (Messenger carol, _) = await relay.user('carol');
    final Conversation g = await alice.createGroup('Trio', <String>['bob', 'carol']);
    await syncAll(<Messenger>[bob, carol], rounds: 1);

    expect(() => bob.removeMember(g.id, 'carol'), throwsA(isA<MessengerException>()));
    final GroupState state = bob.conversations[g.id]!.group!;
    await bob.sendRawPayload(g.id, AppPayload(
      id: bob.freshId(), timestampMs: 0, kind: PayloadKind.group,
      conv: ConvRef.group(state.gid), groupOp: GroupOp.update,
      group: GroupSnapshot(gid: state.gid, version: state.version + 1, name: 'Hijacked',
          members: <String>['alice', 'bob'], admins: <String>['bob']),
    ));
    await syncAll(<Messenger>[alice, carol], rounds: 1);
    expect(alice.conversations[g.id]!.group!.members, containsAll(<String>['alice', 'bob', 'carol']));
    expect(carol.conversations[g.id]!.group!.name, 'Trio');
    expect(carol.conversations[g.id]!.group!.removed, isFalse);
  });

  test('a removed member receives nothing sent after removal', () async {
    final (Messenger alice, _) = await relay.user('alice');
    final (Messenger bob, _) = await relay.user('bob');
    final (Messenger carol, _) = await relay.user('carol');
    final Conversation g = await alice.createGroup('Trio', <String>['bob', 'carol']);
    await alice.sendText(g.id, 'before removal');
    await syncAll(<Messenger>[bob, carol], rounds: 1);

    await alice.removeMember(g.id, 'carol');
    await alice.sendText(g.id, 'after removal');
    await syncAll(<Messenger>[bob, carol], rounds: 1);

    expect(bodies(bob, g.id), <String>['before removal', 'after removal']);
    expect(bodies(carol, g.id), <String>['before removal']);
    expect(carol.conversations[g.id]!.group!.removed, isTrue);
    expect(() => carol.sendText(g.id, 'still here?'), throwsA(isA<MessengerException>()));
  });

  test('a new member gets no history from before they joined', () async {
    final (Messenger alice, _) = await relay.user('alice');
    final (Messenger bob, _) = await relay.user('bob');
    final (Messenger carol, _) = await relay.user('carol');
    final Conversation g = await alice.createGroup('Duo', <String>['bob']);
    await alice.sendText(g.id, 'secret before carol');
    await alice.addMembers(g.id, <String>['carol']);
    await alice.sendText(g.id, 'welcome carol');
    await syncAll(<Messenger>[bob, carol], rounds: 1);

    expect(bodies(carol, g.id), <String>['welcome carol']);
    expect(bodies(bob, g.id), <String>['secret before carol', 'welcome carol']);
    expect(carol.conversations[g.id]!.group!.members, containsAll(<String>['alice', 'bob', 'carol']));
  });

  test('leaving a group stops delivery and promotes an admin if needed', () async {
    final (Messenger alice, _) = await relay.user('alice');
    final (Messenger bob, _) = await relay.user('bob');
    final Conversation g = await alice.createGroup('Pair', <String>['bob']);
    await bob.sync();
    await alice.leaveGroup(g.id);
    await bob.sync();
    final GroupState atBob = bob.conversations[g.id]!.group!;
    expect(atBob.members, <String>['bob']);
    expect(atBob.admins, <String>['bob'], reason: 'the last admin left; a member is promoted');
  });

  // ---------------------------------------------------------- PQ policy

  test('a contact without PQ prekeys is refused until classical is explicitly allowed',
      () async {
    final (Messenger alice, _) = await relay.user('alice');

    // A legacy device that publishes only classical prekeys.
    final RelayClient legacy = relay.client();
    await legacy.register('legacy', testPassword);
    await legacy.login('legacy', testPassword);
    final IdentityKeyPair id = await IdentityKeyPair.generate();
    await legacy.registerDevice(deviceId: 'legacy-device', identityPublic: id.public.toJson());
    final PreKeyStore store = PreKeyStore(id);
    await store.rotateSignedPreKey();
    await legacy.publishPreKeys(
        deviceId: 'legacy-device',
        signedPreKey: store.currentSignedPreKey,
        oneTimePreKeys: await store.generateOneTimePreKeys(3));

    final Conversation c = await alice.openDirect('legacy');
    final ChatMessage refused = await alice.sendText(c.id, 'hello?');
    expect(refused.status, MessageStatus.failed);
    expect(refused.failureReason, contains('post-quantum'));

    // The user explicitly allows classical contacts; the downgrade is labelled.
    await alice.updateSettings((AppSettings s) => s.allowClassical = true);
    await alice.retryMessage(c.id, refused.id);
    expect(refused.status, MessageStatus.sent);
    expect(alice.sessionWith('legacy-device')!.kex, 'x3dh');
    expect(c.messages.any((ChatMessage m) => m.system && m.body.contains('CLASSICAL')), isTrue);

    // The legacy device can read it — classical X3DH, explicitly accepted.
    final QueuedMessage q = (await legacy.fetchMessages()).single;
    final Session s = await startAsResponder(
        identity: id, localDeviceId: 'legacy-device', prekeys: store,
        envelope: q.envelope!, acceptClassical: true);
    expect(AppPayload.decode(await s.decryptMessage(q.envelope!)).body, 'hello?');
  });

  test('profiles travel end to end and appear at the contact', () async {
    final (Messenger alice, _) = await relay.user('alice');
    final (Messenger bob, _) = await relay.user('bob');
    await alice.updateProfile(displayName: 'Alice Liddell');
    await alice.sendText((await alice.openDirect('bob')).id, 'hi');
    await bob.sync();
    expect(bob.contacts['alice']!.displayName, 'Alice Liddell');
    expect(bob.titleOf(bob.conversations['d:alice']!), 'Alice Liddell');
  });

  test('safety numbers match on both sides and verification is per device', () async {
    final (Messenger alice, _) = await relay.user('alice');
    final (Messenger bob, _) = await relay.user('bob');
    final Conversation c = await alice.openDirect('bob');
    await alice.sendText(c.id, 'hi');
    await bob.sync();
    final List<DeviceSafety> a = await alice.safetyNumbersFor('bob');
    final List<DeviceSafety> b = await bob.safetyNumbersFor('alice');
    expect(a.single.safetyNumber, b.single.safetyNumber);
    expect(alice.isVerified(c), isFalse);
    await alice.setDeviceVerified(a.single.pin.deviceId, true);
    expect(alice.isVerified(c), isTrue);
  });

  test('scanning a contact\'s code verifies exactly that device, and only on a full match', () async {
    final (Messenger alice, _) = await relay.user('alice');
    final (Messenger bob, _) = await relay.user('bob');
    final (Messenger carol, _) = await relay.user('carol');
    final Conversation a2b = await alice.openDirect('bob');
    await alice.sendText(a2b.id, 'hi');
    await bob.sync();

    // Wrong person's code: nothing is verified, nothing is imported.
    final String carolsCode = (await carol.safetyNumbersFor('alice')).single.qrPayload;
    QrScanOutcome r = await alice.verifyByScannedCode('bob', carolsCode);
    expect(r.check, QrCheck.peerKeyMismatch);
    expect(alice.isVerified(a2b), isFalse);

    // Bob's real code, but showing a key for "alice" that is not Alice's:
    // the man-in-the-middle signal.
    final String forged = qrPayload(bob.identity.public, carol.identity.public);
    r = await alice.verifyByScannedCode('bob', forged);
    expect(r.check, QrCheck.ownKeyMismatch);
    expect(alice.isVerified(a2b), isFalse);

    expect((await alice.verifyByScannedCode('bob', 'https://example.com')).check, QrCheck.notHelo);

    // Bob displays his code for Alice; Alice scans it.
    final String bobsCode = (await bob.safetyNumbersFor('alice')).single.qrPayload;
    r = await alice.verifyByScannedCode('bob', bobsCode);
    expect(r.check, QrCheck.match);
    expect(r.device!.deviceId, bob.deviceId);
    expect(alice.isVerified(a2b), isTrue);
  });

  test('padding hides message length from the relay', () {
    final List<int> sizes = <String>['k', 'a much longer message, still well under a bucket']
        .map((String b) => AppPayload(id: '0' * 32, timestampMs: 0, kind: PayloadKind.msg,
            conv: const ConvRef.direct(), body: b).encode(defaultPaddingPolicy).length)
        .toSet()
        .toList();
    expect(sizes, <int>[256]);
    expect(defaultRandom.bytes(1), hasLength(1));
  });
}
