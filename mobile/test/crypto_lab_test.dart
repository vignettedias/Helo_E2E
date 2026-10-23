/// The Crypto Lab runs the real protocol code; every defence it demonstrates
/// must actually hold. A lab that reported success on a broken defence would
/// be worse than no lab.
library;

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:helo/lab/crypto_lab.dart';
import 'package:helo/ui/widgets/command_palette.dart';

void main() {
  for (final LabExperiment e in labExperiments) {
    test('lab: ${e.title}', () async {
      final LabResult r = await e.run();
      expect(r.passed, isTrue, reason: r.lines.map((LabLine l) => l.text).join('\n'));
      expect(r.lines.last.kind, 'ok');
      expect(r.lines.where((LabLine l) => l.kind == 'fail'), isEmpty);
    }, timeout: const Timeout(Duration(seconds: 60)));
  }

  test('the lab covers the handshake and five attacks', () {
    expect(labExperiments.map((LabExperiment e) => e.id),
        <String>['handshake', 'tamper', 'replay', 'downgrade', 'nopq', 'substitute']);
  });

  test('the command palette filters on every typed word', () {
    void noop() {}
    final List<DeckCommand> all = <DeckCommand>[
      DeckCommand('New chat', Icons.add, noop, hint: 'start'),
      DeckCommand('Crypto X-Ray ON', Icons.add, noop, hint: 'xray relay view'),
      DeckCommand('Panic: wipe this device', Icons.add, noop, hint: 'reset erase'),
    ];
    expect(filterCommands(all, ''), hasLength(3));
    expect(filterCommands(all, 'xray').single.label, 'Crypto X-Ray ON');
    expect(filterCommands(all, 'wipe dev').single.label, startsWith('Panic'));
    expect(filterCommands(all, 'nothing here'), isEmpty);
  });
}
