/// Widget tests for the chat screen's message actions, driven against the
/// REAL relay process (same harness as messenger_test.dart).
///
/// Relay and accounts are set up in setUp (real async); only the UI is driven
/// inside testWidgets. Network work the UI triggers runs in the widget-test
/// zone, so [settle] alternates real waiting with pumps until it completes.
@Timeout(Duration(seconds: 120))
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/gestures.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:helo/domain/messenger.dart';
import 'package:helo/domain/models.dart';
import 'package:helo/ui/screens/chat_view.dart';
import 'package:helo/ui/theme.dart';

import 'support/relay_harness.dart';

late RelayHarness relay;
late Messenger alice;
late Messenger bob;

const String incoming = 'Hey Bob! Got it.';

Widget host(Messenger m, String convId) => MaterialApp(
      theme: buildTheme(Brightness.light),
      home: Scaffold(
        body: ChatView(messenger: m, convId: convId, onOpenInfo: () {}),
      ),
    );

/// Lets real I/O (HTTP to the relay) progress, pumping in between.
Future<void> settle(WidgetTester tester, {int rounds = 6}) async {
  for (int i = 0; i < rounds; i++) {
    await tester.runAsync(() => Future<void>.delayed(const Duration(milliseconds: 150)));
    await tester.pump(const Duration(milliseconds: 100));
  }
}

/// Unmounts the screen and runs out the messenger's short timers (debounced
/// save, typing expiry, idle HTTP connections) that the UI started on the
/// fake clock.
Future<void> finish(WidgetTester tester) async {
  await tester.pumpWidget(const SizedBox());
  await settle(tester, rounds: 2);
  await tester.pump(const Duration(seconds: 10));
  await settle(tester, rounds: 2);
  // HttpClient keeps idle connections for 15 s on a timer of its own.
  await tester.pump(const Duration(seconds: 30));
}

Future<void> openSheet(WidgetTester tester) async {
  await tester.tap(find.text(incoming));
  await tester.pump();
  await tester.pump(const Duration(milliseconds: 500));
}

void main() {
  // The widget-test binding mocks HttpClient (every request answers 400).
  // These tests talk to a real relay, so real sockets are restored.
  setUpAll(() {
    TestWidgetsFlutterBinding.ensureInitialized();
    HttpOverrides.global = null;
  });

  setUp(() async {
    HttpOverrides.global = null;
    relay = await RelayHarness.start();
    alice = (await relay.user('alice')).$1;
    bob = (await relay.user('bob')).$1;
    final Conversation a2b = await alice.openDirect('bob');
    await alice.sendText(a2b.id, incoming);
    await bob.sync();
  });
  tearDown(() async => relay.dispose());

  for (final String gesture in <String>['tap', 'long-press', 'right-click']) {
    testWidgets('$gesture on a bubble opens the actions sheet', (WidgetTester tester) async {
      await tester.pumpWidget(host(bob, 'd:alice'));
      await settle(tester);

      final Finder bubble = find.text(incoming);
      expect(bubble, findsOneWidget);
      switch (gesture) {
        case 'tap':
          await tester.tap(bubble);
        case 'long-press':
          await tester.longPress(bubble);
        case 'right-click':
          await tester.tap(bubble, buttons: kSecondaryMouseButton);
      }
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 500));
      expect(find.text('Reply'), findsOneWidget);
      expect(find.text('Copy text'), findsOneWidget);
      expect(find.text('Forward'), findsOneWidget);
      expect(find.text('Delete for me'), findsOneWidget);
      // Incoming message: no edit, no delete-for-everyone.
      expect(find.text('Edit'), findsNothing);
      expect(find.text('Delete for everyone'), findsNothing);
      await finish(tester);
    });
  }

  testWidgets('own message offers edit and delete for everyone', (WidgetTester tester) async {
    await tester.pumpWidget(host(alice, 'd:bob'));
    await settle(tester);
    await openSheet(tester);
    expect(find.text('Edit'), findsOneWidget);
    expect(find.text('Delete for everyone'), findsOneWidget);
    expect(find.text('Message info'), findsOneWidget);
    await finish(tester);
  });

  testWidgets('reacting from the sheet reaches the other side', (WidgetTester tester) async {
    await tester.pumpWidget(host(bob, 'd:alice'));
    await settle(tester);
    await openSheet(tester);
    await tester.tap(find.text(quickReactions.first).last);
    await settle(tester, rounds: 12);

    await tester.runAsync(() => alice.sync());
    final ChatMessage m =
        alice.conversations['d:bob']!.messages.firstWhere((ChatMessage x) => !x.system);
    expect(m.reactions['bob'], quickReactions.first);
    await finish(tester);
  });

  testWidgets('reply from the sheet sends a quoted message', (WidgetTester tester) async {
    await tester.pumpWidget(host(bob, 'd:alice'));
    await settle(tester);
    await openSheet(tester);
    await tester.tap(find.text('Reply'));
    await tester.pump(const Duration(milliseconds: 500));

    await tester.enterText(find.byType(TextField).last, 'replying now');
    await tester.pump();
    await tester.tap(find.byIcon(Icons.send_rounded));
    await settle(tester, rounds: 12);

    await tester.runAsync(() => alice.sync());
    final ChatMessage r =
        alice.conversations['d:bob']!.messages.lastWhere((ChatMessage x) => !x.system);
    expect(r.body, 'replying now');
    expect(r.reply, isNotNull);
    expect(r.reply!.author, 'alice');
    await finish(tester);
  });
  testWidgets('delete for everyone asks first, then reaches the other side', (WidgetTester tester) async {
    await tester.pumpWidget(host(alice, 'd:bob'));
    await settle(tester);

    // Cancel leaves the message alone.
    await openSheet(tester);
    await tester.tap(find.text('Delete for everyone'));
    await tester.pump(const Duration(milliseconds: 500));
    expect(find.text('Delete for everyone?'), findsOneWidget);
    await tester.tap(find.text('Cancel'));
    await settle(tester);
    expect(find.text(incoming), findsOneWidget);

    await openSheet(tester);
    await tester.tap(find.text('Delete for everyone'));
    await tester.pump(const Duration(milliseconds: 500));
    await tester.tap(find.widgetWithText(FilledButton, 'Delete'));
    await settle(tester, rounds: 12);
    expect(find.text(incoming), findsNothing);

    await tester.runAsync(() => bob.sync());
    final ChatMessage m =
        bob.conversations['d:alice']!.messages.firstWhere((ChatMessage x) => !x.system);
    expect(m.deleted, isTrue);
    expect(m.body, isEmpty);
    await finish(tester);
  });

  testWidgets('a received voice note shows as a voice player, not a file', (WidgetTester tester) async {
    await tester.runAsync(() async {
      await alice.sendAttachment('d:bob', Uint8List.fromList(List<int>.filled(4000, 0)),
          name: 'voice-1.wav', mime: 'audio/wav', voice: true, durationMs: 7000);
      await bob.sync();
    });
    await tester.pumpWidget(host(bob, 'd:alice'));
    await settle(tester);
    expect(find.text('Voice message'), findsOneWidget);
    expect(find.byTooltip('Play'), findsOneWidget);
    expect(find.textContaining('0:07'), findsOneWidget, reason: 'sender-reported length before playback');
    expect(find.text('voice-1.wav'), findsNothing);
    await finish(tester);
  });

  testWidgets('recording without a microphone fails safe and returns to the text box',
      (WidgetTester tester) async {
    await tester.pumpWidget(host(bob, 'd:alice'));
    await settle(tester);
    await tester.tap(find.byTooltip('Record a voice message'));
    await tester.pump();
    await settle(tester, rounds: 3);
    // No recorder plugin in the test VM: the bar must not hang or send anything.
    expect(find.byTooltip('Send voice message'), findsNothing);
    expect(find.byType(TextField), findsWidgets);
    expect(find.textContaining('microphone', findRichText: true), findsOneWidget);
    await finish(tester);
  });
}
