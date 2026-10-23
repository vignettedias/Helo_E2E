/// The Crypto Lab screen runs every experiment and prints a verdict.
library;

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:helo/ui/screens/crypto_lab_screen.dart';
import 'package:helo/ui/theme.dart';

void main() {
  testWidgets('RUN ALL prints every experiment and a 6/6 summary', (WidgetTester tester) async {
    await tester.pumpWidget(MaterialApp(theme: buildTheme(Brightness.dark), home: const CryptoLabScreen()));
    await tester.tap(find.text('RUN ALL'));
    for (int i = 0; i < 400 && find.textContaining('SUMMARY').evaluate().isEmpty; i++) {
      await tester.runAsync(() => Future<void>.delayed(const Duration(milliseconds: 20)));
      await tester.pump(const Duration(milliseconds: 200));
    }
    expect(find.textContaining('SUMMARY: 6/6 defences held'), findsOneWidget);
    expect(find.textContaining('[FAIL]'), findsNothing);
    await tester.pump(const Duration(seconds: 1)); // let the last line's delay finish
  }, timeout: const Timeout(Duration(seconds: 120)));
}
