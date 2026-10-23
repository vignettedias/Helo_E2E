/// Crypto Lab: a terminal that runs the real handshake and real attacks
/// (lib/lab/crypto_lab.dart) and prints what happened, line by line.
library;

import 'dart:async';

import 'package:flutter/material.dart';

import '../../lab/crypto_lab.dart';
import '../theme.dart';

class CryptoLabScreen extends StatefulWidget {
  const CryptoLabScreen({super.key});

  @override
  State<CryptoLabScreen> createState() => _CryptoLabScreenState();
}

class _Entry {
  _Entry(this.kind, this.text);
  final String kind; // prompt | step | data | ok | fail | note
  final String text;
}

class _CryptoLabScreenState extends State<CryptoLabScreen> {
  final List<_Entry> _log = <_Entry>[
    _Entry('note', 'HELO crypto lab — every experiment runs the real protocol code on throwaway'),
    _Entry('note', 'identities in this browser tab. Nothing touches your account or the relay.'),
  ];
  final ScrollController _scroll = ScrollController();
  final Map<String, bool> _results = <String, bool>{};
  bool _busy = false;

  @override
  void dispose() {
    _scroll.dispose();
    super.dispose();
  }

  Future<void> _emit(_Entry e) async {
    if (!mounted) return;
    setState(() => _log.add(e));
    final bool still = MediaQuery.disableAnimationsOf(context);
    await Future<void>.delayed(Duration(milliseconds: still ? 0 : 140));
    if (_scroll.hasClients) {
      _scroll.jumpTo(_scroll.position.maxScrollExtent);
    }
  }

  Future<void> _run(List<LabExperiment> which) async {
    if (_busy) return;
    setState(() => _busy = true);
    for (final LabExperiment e in which) {
      await _emit(_Entry('prompt', 'helo-lab:~\$ run ${e.id}'));
      await _emit(_Entry('note', '# ${e.blurb}'));
      LabResult r;
      try {
        r = await e.run();
      } on Object catch (err) {
        r = LabResult(false, <LabLine>[LabLine('fail', 'experiment crashed: ${err.runtimeType}')]);
      }
      for (final LabLine l in r.lines) {
        await _emit(_Entry(l.kind, l.text));
      }
      _results[e.id] = r.passed;
    }
    if (which.length > 1) {
      final int ok = _results.values.where((bool v) => v).length;
      await _emit(_Entry(ok == _results.length ? 'ok' : 'fail',
          'SUMMARY: $ok/${_results.length} defences held'));
    }
    if (mounted) setState(() => _busy = false);
  }

  @override
  Widget build(BuildContext context) {
    final HeloPalette p = HeloPalette.of(context);
    Color colorOf(String kind) => switch (kind) {
          'prompt' => p.accent,
          'ok' => p.success,
          'fail' => p.danger,
          'data' => p.info,
          'note' => p.textFaint,
          _ => p.textPrimary,
        };
    return Scaffold(
      appBar: AppBar(title: const Text('crypto lab')),
      body: Column(children: <Widget>[
        Padding(
          padding: const EdgeInsets.fromLTRB(12, 10, 12, 4),
          child: Wrap(spacing: 8, runSpacing: 8, children: <Widget>[
            FilledButton.icon(
              onPressed: _busy ? null : () => _run(labExperiments),
              icon: const Icon(Icons.play_arrow_rounded),
              label: const Text('RUN ALL'),
            ),
            for (final LabExperiment e in labExperiments)
              OutlinedButton(
                onPressed: _busy ? null : () => _run(<LabExperiment>[e]),
                style: OutlinedButton.styleFrom(
                  foregroundColor: _results[e.id] == null
                      ? null
                      : (_results[e.id]! ? p.success : p.danger),
                ),
                child: Text(e.title, style: const TextStyle(fontSize: 12)),
              ),
          ]),
        ),
        Expanded(
          child: Container(
            margin: const EdgeInsets.all(12),
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: p.backdrop,
              border: Border.all(color: p.border),
              borderRadius: BorderRadius.circular(4),
            ),
            child: ListView.builder(
              controller: _scroll,
              itemCount: _log.length + (_busy ? 1 : 0),
              itemBuilder: (BuildContext _, int i) {
                if (i == _log.length) {
                  return Text('▌', style: TextStyle(fontFamily: heloMono, color: p.accent));
                }
                final _Entry e = _log[i];
                final String mark = switch (e.kind) {
                  'ok' => '[ OK ] ',
                  'fail' => '[FAIL] ',
                  'step' => '  ··  ',
                  'data' => '   >  ',
                  _ => '',
                };
                return Padding(
                  padding: EdgeInsets.only(top: e.kind == 'prompt' ? 10 : 1),
                  child: SelectableText('$mark${e.text}',
                      style: TextStyle(fontFamily: heloMono, fontSize: 12.5, height: 1.35,
                          color: colorOf(e.kind),
                          fontWeight: e.kind == 'ok' || e.kind == 'fail' ? FontWeight.w700 : null)),
                );
              },
            ),
          ),
        ),
      ]),
    );
  }
}
