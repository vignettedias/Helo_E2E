/// Every request this client has made to the relay: method, path, status,
/// sizes, timing. Exactly what a network observer sees — and no more, which
/// is the point worth showing.
library;

import 'package:flutter/material.dart';

import '../../data/relay_client.dart';
import '../../domain/messenger.dart';
import '../format.dart';
import '../theme.dart';

class NetworkScreen extends StatelessWidget {
  const NetworkScreen({required this.messenger, super.key});

  final Messenger messenger;

  @override
  Widget build(BuildContext context) {
    final HeloPalette p = HeloPalette.of(context);
    const TextStyle mono = TextStyle(fontFamily: heloMono, fontSize: 11.5, height: 1.5);
    return Scaffold(
      appBar: AppBar(title: const Text('network inspector')),
      body: ValueListenableBuilder<int>(
        valueListenable: messenger.relay.trafficVersion,
        builder: (BuildContext context, int _, Widget? __) {
          final List<RelayCall> calls = messenger.relay.calls;
          final int up = calls.fold(0, (int a, RelayCall c) => a + c.requestBytes);
          final int down = calls.fold(0, (int a, RelayCall c) => a + c.responseBytes);
          return Center(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 880),
              child: Column(children: <Widget>[
                Padding(
                  padding: const EdgeInsets.fromLTRB(16, 12, 16, 6),
                  child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: <Widget>[
                    Text('${calls.length} request(s) · ${fileSize(up)} sent · ${fileSize(down)} received',
                        style: mono.copyWith(color: p.accent)),
                    const SizedBox(height: 4),
                    Text(
                      'Bodies are ciphertext the relay cannot read; this list holds no headers '
                      '(your bearer token) and no message content.',
                      style: TextStyle(color: p.textFaint, fontSize: 11.5),
                    ),
                  ]),
                ),
                Divider(height: 1, color: p.border),
                Expanded(
                  child: calls.isEmpty
                      ? Center(child: Text('no traffic yet', style: TextStyle(color: p.textFaint)))
                      : ListView.builder(
                          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                          itemCount: calls.length,
                          itemBuilder: (BuildContext _, int i) {
                            final RelayCall c = calls[i];
                            final Color status = c.status == 0
                                ? p.warning
                                : (c.ok ? p.success : p.danger);
                            return Padding(
                              padding: const EdgeInsets.symmetric(vertical: 1),
                              child: Row(children: <Widget>[
                                SizedBox(width: 52, child: Text(clock(c.at), style: mono.copyWith(color: p.textFaint))),
                                SizedBox(width: 52, child: Text(c.method, style: mono.copyWith(color: p.info))),
                                Expanded(child: Text(c.path, style: mono, overflow: TextOverflow.ellipsis)),
                                SizedBox(
                                  width: 44,
                                  child: Text(c.status == 0 ? '—' : '${c.status}',
                                      style: mono.copyWith(color: status, fontWeight: FontWeight.w700)),
                                ),
                                SizedBox(
                                  width: 128,
                                  child: Text(
                                    '↑${fileSize(c.requestBytes)} ↓${fileSize(c.responseBytes)}',
                                    style: mono.copyWith(color: p.textSecondary),
                                    textAlign: TextAlign.right,
                                  ),
                                ),
                                SizedBox(
                                  width: 64,
                                  child: Text('${c.milliseconds} ms',
                                      style: mono.copyWith(color: p.textFaint), textAlign: TextAlign.right),
                                ),
                              ]),
                            );
                          },
                        ),
                ),
              ]),
            ),
          );
        },
      ),
    );
  }
}
