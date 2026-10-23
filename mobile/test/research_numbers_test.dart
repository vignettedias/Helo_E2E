/// Every measured number the app displays must still equal the measurement.
///
/// The app shows figures from the experiments (padding leakage, handshake
/// cost, what the relay database holds). Re-running an experiment changes
/// `research/results/*.json`; this test fails if the copies in the app were
/// not updated with it, so the UI can never quietly show stale or invented
/// numbers.
library;

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:helo/research_numbers.dart';

Map<String, dynamic> _load(String name) =>
    jsonDecode(File('../research/results/$name').readAsStringSync()) as Map<String, dynamic>;

void main() {
  test('E1 padding figures match scripts/experiments/padding_overhead.py', () {
    final Map<String, dynamic> all =
        _load('padding_overhead.json')['distributions'] as Map<String, dynamic>;
    final Map<String, dynamic> dist = all['short_chat_lognormal'] as Map<String, dynamic>;
    expect(paddingE1.keys.toSet(), dist.keys.toSet(), reason: 'a policy was added or removed');
    for (final MapEntry<String, (double, double)> e in paddingE1.entries) {
      final Map<String, dynamic> m = dist[e.key] as Map<String, dynamic>;
      expect((m['leakage_bits'] as num).toDouble(), e.value.$1, reason: '${e.key} leakage');
      expect((m['mean_overhead_bytes'] as num).toDouble(), e.value.$2, reason: '${e.key} overhead');
    }
  });

  test('E2 handshake figures match scripts/experiments/handshake_cost.py', () {
    final Map<String, dynamic> h = _load('handshake_cost.json');
    final Map<String, dynamic> classical = h['classical'] as Map<String, dynamic>;
    final Map<String, dynamic> hybrid = h['hybrid'] as Map<String, dynamic>;
    expect(((classical['initiator'] as Map<String, dynamic>)['median_ms'] as num).toDouble(),
        handshakeClassicalMedianMs);
    expect(((hybrid['initiator'] as Map<String, dynamic>)['median_ms'] as num).toDouble(),
        handshakeHybridMedianMs);
    expect(classical['first_envelope_json_bytes'], firstEnvelopeClassicalBytes);
    expect(hybrid['first_envelope_json_bytes'], firstEnvelopeHybridBytes);
  });

  test('E3 relay-database figures match scripts/experiments/metadata_inventory.py', () {
    final Map<String, dynamic> m = _load('metadata_inventory.json');
    final Map<String, dynamic> classes = m['column_classes'] as Map<String, dynamic>;
    expect(classes['METADATA'], relayColumnsMetadata);
    expect(classes['CIPHERTEXT'], relayColumnsCiphertext);

    int distinct(String policy) {
      final Map<String, dynamic> run = (m['runs'] as Map<String, dynamic>)[policy] as Map<String, dynamic>;
      final Map<String, dynamic> queued = run['queued'] as Map<String, dynamic>;
      return (queued['sizes'] as List<Object?>).toSet().length;
    }
    expect(distinct('none'), storedSizesUnpadded);
    expect(distinct('block-256'), storedSizesPadded);
  });
}
