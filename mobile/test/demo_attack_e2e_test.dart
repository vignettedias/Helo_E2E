/// The attack simulator, end to end: a REAL relay started with DEMO_ATTACKS=1
/// misbehaves, and real Messenger clients refuse it.
///
/// These are the demonstrations shown on screen in the attack screen, so the
/// claim "the client rejects this" is asserted here rather than narrated.
@Timeout(Duration(seconds: 120))
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:helo/domain/messenger.dart';
import 'package:helo/domain/directory.dart';
import 'package:helo/domain/models.dart';

import 'support/relay_harness.dart';

late RelayHarness relay;

void main() {
  setUp(() async => relay = await RelayHarness.start(demoAttacks: true));
  tearDown(() async => relay.dispose());

  /// Alice and Bob with one delivered message each way, so sessions exist.
  Future<(Messenger, Messenger)> talking() async {
    final (Messenger alice, _) = await relay.user('alice');
    final (Messenger bob, _) = await relay.user('bob');
    await alice.sendText((await alice.openDirect('bob')).id, 'hello');
    await bob.sync();
    await bob.sendText('d:alice', 'hi back');
    await alice.sync();
    return (alice, bob);
  }

  List<String> bodiesOf(Messenger m, String convId) => m.conversations[convId]!.messages
      .where((ChatMessage x) => !x.system)
      .map((ChatMessage x) => x.body)
      .toList();

  test('the switch is reachable only because this relay was started for a demo', () async {
    final (Messenger alice, _) = await relay.user('alice');
    final Map<String, dynamic>? state = await alice.relay.demoAttackState();
    expect(state, isNotNull);
    expect(state!['mode'], 'none');
    expect((state['attacks'] as Map<String, dynamic>).keys,
        containsAll(<String>['tamper', 'replay', 'strip_pq', 'substitute_identity']));

    final RelayHarness honest = await RelayHarness.start();
    addTearDown(honest.dispose);
    final (Messenger carol, _) = await honest.user('carol');
    expect(await carol.relay.demoAttackState(), isNull,
        reason: 'a relay started normally has no attack switch at all');
  });

  test('tamper: a flipped bit is refused and reported, not shown', () async {
    final (Messenger alice, Messenger bob) = await talking();
    await alice.relay.setDemoAttack('tamper');
    await alice.sendText('d:bob', 'transfer 10 to mallory');
    await bob.sync();

    expect(bodiesOf(bob, 'd:alice'), <String>['hello', 'hi back'],
        reason: 'the tampered message must never appear');
    expect(bob.incidents, isNotEmpty);
    expect(bob.incidents.first.errorClass, 'AuthenticationError');
    expect(bob.incidents.first.sender, 'alice');
    expect(bob.incidents.first.explanation, contains('altered in transit'));
    // And the chat says so, rather than silently losing a message.
    expect(bob.conversations['d:alice']!.messages.any((ChatMessage m) => m.system && m.body.contains('REFUSED')),
        isTrue);

    // Disarming restores normal delivery on the same session.
    await alice.relay.setDemoAttack('none');
    await alice.sendText('d:bob', 'honest again');
    await bob.sync();
    expect(bodiesOf(bob, 'd:alice'), contains('honest again'));
  });

  test('replay: the second copy is refused, the first still arrives', () async {
    final (Messenger alice, Messenger bob) = await talking();
    await alice.relay.setDemoAttack('replay');
    await alice.sendText('d:bob', 'approve the payment');
    await bob.sync();

    expect(bodiesOf(bob, 'd:alice').where((String b) => b == 'approve the payment'), hasLength(1),
        reason: 'delivered twice by the relay, shown once');
    expect(bob.incidents.first.errorClass, 'ReplayError');
  });

  test('strip_pq: the sender refuses a bundle with the ML-KEM key removed', () async {
    final (Messenger alice, _) = await relay.user('alice');
    await relay.user('bob');
    await alice.relay.setDemoAttack('strip_pq');

    final Conversation c = await alice.openDirect('bob');
    final ChatMessage m = await alice.sendText(c.id, 'first contact');
    expect(m.status, MessageStatus.failed, reason: 'no session may be built on the weaker handshake');
    expect(m.failureReason, contains('post-quantum'));
  });

  test('substitute_identity: a swapped key is pinned as a conflict and nothing is sent to it', () async {
    final (Messenger alice, Messenger bob) = await talking();
    expect(alice.hasConflict(alice.conversations['d:bob']!), isFalse);

    await alice.relay.setDemoAttack('substitute_identity');
    // Sends reuse a cached directory entry, so the swap is only observable on
    // a real fetch: re-check the contact's keys, as the UI button does.
    final DirectoryLookup found = await alice.refreshDevices('bob');
    expect(found.conflicts, isNotEmpty);
    final ChatMessage m = await alice.sendText('d:bob', 'after the swap');

    expect(alice.hasConflict(alice.conversations['d:bob']!), isTrue,
        reason: 'the pinned key no longer matches what the relay serves');
    expect(m.status, MessageStatus.failed);
    await bob.sync();
    expect(bodiesOf(bob, 'd:alice'), isNot(contains('after the swap')));
  });
}
