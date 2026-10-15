/// Developer diagnostics.
///
/// Everything shown here is a truncated hash, a counter, or a state label.
/// NO private key, root key, chain key, message key, or plaintext appears —
/// enforced by Session.diagnostics(), which constructs the map from safe
/// values only rather than filtering a dump after the fact.
library;

import 'package:flutter/material.dart';

import '../../domain/session_manager.dart';
import '../theme.dart';

class DiagnosticsScreen extends StatelessWidget {
  const DiagnosticsScreen({required this.manager, super.key});
  final SessionManager manager;

  @override
  Widget build(BuildContext context) {
    final List<Conversation> conversations =
        manager.conversations.values.toList();

    return Scaffold(
      appBar: AppBar(title: const Text('Diagnostics')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: <Widget>[
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: HeloColors.surface,
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: HeloColors.border),
            ),
            child: const Text(
              'This screen shows protocol state for debugging. It contains no '
              'key material: every identifier is a truncated hash.',
              style: TextStyle(color: HeloColors.textFaint, fontSize: 11),
            ),
          ),
          const SizedBox(height: 16),
          _row('account', manager.username ?? '—'),
          _row('device id', manager.deviceId),
          _row('relay', manager.relay.baseUrl),
          _row('protocol', 'Helo/1 X3DH + DoubleRatchet + AES-256-GCM'),
          _row('post-quantum', 'NO \u2014 classical X25519 only'),
          _row('local prekeys', '${_prekeyCount(manager)}'),
          const SizedBox(height: 20),
          const Text('SESSIONS',
              style: TextStyle(
                  fontSize: 11,
                  color: HeloColors.textFaint,
                  letterSpacing: 1.5)),
          const SizedBox(height: 8),
          if (conversations.isEmpty)
            const Text('none',
                style:
                    TextStyle(color: HeloColors.textFaint, fontSize: 12))
          else
            ...conversations.map((Conversation c) => _SessionCard(c)),
        ],
      ),
    );
  }

  int _prekeyCount(SessionManager m) {
    try {
      return m.prekeys.oneTimePreKeyCount;
    } catch (_) {
      return 0;
    }
  }

  static Widget _row(String label, String value) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 5),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            SizedBox(
              width: 130,
              child: Text(label,
                  style: const TextStyle(
                      color: HeloColors.textFaint, fontSize: 11.5)),
            ),
            Expanded(
              child: Text(value, style: const TextStyle(fontSize: 11.5)),
            ),
          ],
        ),
      );
}

class _SessionCard extends StatelessWidget {
  const _SessionCard(this.conversation);
  final Conversation conversation;

  @override
  Widget build(BuildContext context) {
    return FutureBuilder<Map<String, Object?>>(
      future: conversation.session.diagnostics(),
      builder: (BuildContext ctx,
          AsyncSnapshot<Map<String, Object?>> snapshot) {
        final Map<String, Object?>? data = snapshot.data;
        return Card(
          margin: const EdgeInsets.only(bottom: 12),
          child: Padding(
            padding: const EdgeInsets.all(14),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: <Widget>[
                Text(conversation.peerDeviceId,
                    style: const TextStyle(
                        fontSize: 13, fontWeight: FontWeight.w600)),
                const SizedBox(height: 10),
                if (data == null)
                  const Text('computing\u2026',
                      style: TextStyle(
                          color: HeloColors.textFaint, fontSize: 11))
                else
                  ...data.entries.map(
                    (MapEntry<String, Object?> e) =>
                        DiagnosticsScreen._row(e.key, '${e.value}'),
                  ),
              ],
            ),
          ),
        );
      },
    );
  }
}
