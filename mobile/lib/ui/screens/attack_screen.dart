/// Arm the relay's demo attacks and watch this device refuse them.
///
/// The attacks are performed by the REAL relay (backend/src/routes/demo.js)
/// and refused by the REAL protocol code; this screen only arms them and
/// shows what came back. If the relay was not started with DEMO_ATTACKS=1 the
/// switch does not exist, and this screen says so instead of pretending.
library;

import 'dart:async';

import 'package:flutter/material.dart';

import '../../domain/messenger.dart';
import '../../domain/models.dart';
import '../format.dart';
import '../theme.dart';

class AttackScreen extends StatefulWidget {
  const AttackScreen({required this.messenger, super.key});

  final Messenger messenger;

  @override
  State<AttackScreen> createState() => _AttackScreenState();
}

class _AttackScreenState extends State<AttackScreen> {
  Messenger get _m => widget.messenger;
  StreamSubscription<void>? _sub;
  Map<String, dynamic>? _state;
  bool _loading = true;
  String? _error;
  String? _busyMode;

  @override
  void initState() {
    super.initState();
    _sub = _m.changes.listen((_) {
      if (mounted) setState(() {});
    });
    unawaited(_load());
  }

  @override
  void dispose() {
    unawaited(_sub?.cancel());
    super.dispose();
  }

  Future<void> _load() async {
    try {
      final Map<String, dynamic>? s = await _m.relay.demoAttackState();
      if (mounted) setState(() => _state = s);
    } on Object catch (e) {
      if (mounted) setState(() => _error = '$e');
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _arm(String mode) async {
    setState(() => _busyMode = mode);
    try {
      await _m.relay.setDemoAttack(mode);
      await _load();
    } on Object catch (e) {
      if (mounted) setState(() => _error = '$e');
    } finally {
      if (mounted) setState(() => _busyMode = null);
    }
  }

  Future<void> _recheck() async {
    final List<String> peers = _m.conversations.values
        .where((Conversation c) => !c.isGroup)
        .map((Conversation c) => c.peer!)
        .toList();
    for (final String u in peers) {
      try {
        await _m.refreshDevices(u);
      } on Object {
        // offline or blocked: nothing to report here
      }
    }
    if (mounted) setState(() {});
  }

  @override
  Widget build(BuildContext context) {
    final HeloPalette p = HeloPalette.of(context);
    return Scaffold(
      appBar: AppBar(title: const Text('attack simulator')),
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 820),
          child: ListView(padding: const EdgeInsets.all(16), children: <Widget>[
            if (_loading)
              const Padding(padding: EdgeInsets.all(24), child: LinearProgressIndicator())
            else if (_state == null)
              _disabledCard(p)
            else
              ..._armingCards(p),
            if (_error != null)
              Padding(
                padding: const EdgeInsets.only(top: 10),
                child: Text(_error!, style: TextStyle(color: p.danger, fontSize: 12)),
              ),
            const SizedBox(height: 18),
            _incidentsCard(p),
          ]),
        ),
      ),
    );
  }

  Widget _disabledCard(HeloPalette p) => Card(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: <Widget>[
            Row(children: <Widget>[
              Icon(Icons.shield_outlined, color: p.success),
              const SizedBox(width: 8),
              const Text('This relay cannot be told to attack you.',
                  style: TextStyle(fontWeight: FontWeight.w700)),
            ]),
            const SizedBox(height: 8),
            Text(
              'The attack routes do not exist unless the relay process was started with '
              'DEMO_ATTACKS=1. That is the intended state for anything but a demonstration.',
              style: TextStyle(color: p.textSecondary, fontSize: 12.5),
            ),
            const SizedBox(height: 10),
            SelectableText('DEMO_ATTACKS=1 python scripts/run_demo.py',
                style: TextStyle(fontFamily: heloMono, fontSize: 12, color: p.info)),
            const SizedBox(height: 6),
            Text('Stop the demo, run that, and reload this page.',
                style: TextStyle(color: p.textFaint, fontSize: 11.5)),
          ]),
        ),
      );

  List<Widget> _armingCards(HeloPalette p) {
    final Map<String, dynamic> attacks = _state!['attacks'] as Map<String, dynamic>;
    final String mode = '${_state!['mode']}';
    return <Widget>[
      Container(
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: p.danger.withValues(alpha: 0.08),
          border: Border.all(color: p.danger.withValues(alpha: 0.5)),
          borderRadius: BorderRadius.circular(4),
        ),
        child: Row(children: <Widget>[
          Icon(Icons.warning_amber_rounded, color: p.danger),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              'DEMO MODE: this relay will corrupt, duplicate, strip or swap what it serves to '
              'EVERY client connected to it. Arm one attack, send a message from the other '
              'window, and watch it be refused below.',
              style: TextStyle(color: p.textSecondary, fontSize: 12.5),
            ),
          ),
        ]),
      ),
      const SizedBox(height: 12),
      for (final MapEntry<String, dynamic> e in attacks.entries)
        _attackTile(p, e.key, e.value as Map<String, dynamic>, armed: e.key == mode),
      const SizedBox(height: 10),
      OutlinedButton.icon(
        onPressed: _recheck,
        icon: const Icon(Icons.refresh_rounded, size: 18),
        label: const Text('Re-check every contact\'s keys now'),
      ),
      Padding(
        padding: const EdgeInsets.only(top: 4, left: 2),
        child: Text(
          'Sends reuse a cached directory entry for a few minutes, so a swapped key is only '
          'seen on a real lookup. This forces one.',
          style: TextStyle(color: p.textFaint, fontSize: 11.5),
        ),
      ),
    ];
  }

  Widget _attackTile(HeloPalette p, String id, Map<String, dynamic> info, {required bool armed}) {
    final bool none = id == 'none';
    return Card(
      color: armed && !none ? p.danger.withValues(alpha: 0.10) : null,
      child: ListTile(
        leading: Icon(
          none ? Icons.verified_user_outlined : Icons.bug_report_outlined,
          color: armed ? (none ? p.success : p.danger) : p.textFaint,
        ),
        title: Text(id, style: const TextStyle(fontFamily: heloMono, fontWeight: FontWeight.w700)),
        subtitle: Column(crossAxisAlignment: CrossAxisAlignment.start, children: <Widget>[
          Text('${info['does']}', style: TextStyle(color: p.textSecondary, fontSize: 12)),
          if (!none)
            Text('caught by: ${info['caught_by']}',
                style: TextStyle(color: p.info, fontSize: 11.5)),
        ]),
        trailing: _busyMode == id
            ? const SizedBox(width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2))
            : armed
                ? Text('ARMED', style: TextStyle(color: none ? p.success : p.danger, fontSize: 11))
                : TextButton(onPressed: () => _arm(id), child: Text(none ? 'Disarm' : 'Arm')),
      ),
    );
  }

  Widget _incidentsCard(HeloPalette p) {
    final List<SecurityIncident> all = _m.incidents;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: <Widget>[
          Row(children: <Widget>[
            Icon(Icons.gpp_maybe_outlined, size: 18, color: p.accent),
            const SizedBox(width: 8),
            const Text('Refused by this device', style: TextStyle(fontWeight: FontWeight.w700)),
          ]),
          const SizedBox(height: 8),
          if (all.isEmpty)
            Text('Nothing refused yet. Arm an attack, then send a message from the other window.',
                style: TextStyle(color: p.textFaint, fontSize: 12))
          else
            for (final SecurityIncident i in all.take(12))
              Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: <Widget>[
                  Text('${clock(i.at)}  ${i.errorClass}  (from ${i.sender})',
                      style: TextStyle(fontFamily: heloMono, fontSize: 12, color: p.danger)),
                  Text(i.explanation, style: TextStyle(color: p.textSecondary, fontSize: 11.5)),
                ]),
              ),
        ]),
      ),
    );
  }
}
