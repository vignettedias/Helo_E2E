/// Verification dashboard: shows the results of the project's automated
/// security verification, as recorded by `scripts/verify.py`.
///
/// Every status shown comes from that report — a real test run with its time
/// and duration. Nothing here is hard-coded green. If no report is available
/// (e.g. the app is not being served by the demo server), the dashboard says
/// so instead of displaying anything reassuring.
library;

import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

import '../theme.dart';

class VerificationDashboardScreen extends StatefulWidget {
  const VerificationDashboardScreen({required this.relayBase, super.key});
  final String relayBase;

  @override
  State<VerificationDashboardScreen> createState() => _VerificationDashboardScreenState();
}

class _VerificationDashboardScreenState extends State<VerificationDashboardScreen> {
  late Future<Map<String, dynamic>?> _report = _load();

  /// The report is published next to the web app as /verification.json by
  /// scripts/run_demo.py; nothing else produces it.
  Future<Map<String, dynamic>?> _load() async {
    try {
      final Uri uri = Uri.base.resolve('/verification.json');
      final http.Response r = await http.get(uri);
      if (r.statusCode != 200) return null;
      final Object? json = jsonDecode(r.body);
      return json is Map<String, dynamic> ? json : null;
    } on Object {
      return null;
    }
  }

  @override
  Widget build(BuildContext context) {
    final HeloPalette p = HeloPalette.of(context);
    return Scaffold(
      appBar: AppBar(
        title: const Text('Verification dashboard'),
        actions: <Widget>[
          IconButton(
              tooltip: 'Reload',
              icon: const Icon(Icons.refresh_rounded),
              onPressed: () => setState(() => _report = _load())),
        ],
      ),
      body: FutureBuilder<Map<String, dynamic>?>(
        future: _report,
        builder: (BuildContext context, AsyncSnapshot<Map<String, dynamic>?> snap) {
          if (snap.connectionState != ConnectionState.done) {
            return const Center(child: CircularProgressIndicator());
          }
          final Map<String, dynamic>? report = snap.data;
          if (report == null) {
            return Center(
              child: Padding(
                padding: const EdgeInsets.all(28),
                child: Column(mainAxisSize: MainAxisSize.min, children: <Widget>[
                  Icon(Icons.help_outline_rounded, size: 40, color: p.textFaint),
                  const SizedBox(height: 12),
                  const Text('No verification report available', style: TextStyle(fontWeight: FontWeight.w700)),
                  const SizedBox(height: 8),
                  Text(
                    'Status: NOT RUN. Generate one with "python scripts/verify.py" and serve the app with '
                    '"python scripts/run_demo.py". This screen never shows results it did not receive.',
                    textAlign: TextAlign.center,
                    style: TextStyle(color: p.textSecondary),
                  ),
                ]),
              ),
            );
          }
          return _ReportView(report: report);
        },
      ),
    );
  }
}

class _ReportView extends StatelessWidget {
  const _ReportView({required this.report});
  final Map<String, dynamic> report;

  static (Color, IconData) styleFor(HeloPalette p, String status) => switch (status) {
        'PASS' => (p.success, Icons.check_circle_rounded),
        'FAIL' => (p.danger, Icons.cancel_rounded),
        'BLOCKED' => (p.warning, Icons.block_rounded),
        'EXPERIMENTAL' => (p.info, Icons.science_outlined),
        'NOT VERIFIED' => (p.warning, Icons.help_outline_rounded),
        _ => (p.textFaint, Icons.remove_circle_outline_rounded), // NOT RUN
      };

  @override
  Widget build(BuildContext context) {
    final HeloPalette p = HeloPalette.of(context);
    final List<Map<String, dynamic>> suites =
        (report['suites'] as List<Object?>? ?? <Object?>[]).whereType<Map<String, dynamic>>().toList();
    final Map<String, dynamic> totals = report['totals'] as Map<String, dynamic>? ?? <String, dynamic>{};
    return Center(
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 860),
        child: ListView(padding: const EdgeInsets.all(16), children: <Widget>[
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: <Widget>[
                Text('Run ${report['generated_at'] ?? 'unknown time'}',
                    style: const TextStyle(fontWeight: FontWeight.w700)),
                const SizedBox(height: 4),
                Text('${report['environment'] ?? ''}', style: TextStyle(color: p.textFaint, fontSize: 12)),
                const SizedBox(height: 10),
                Wrap(spacing: 14, runSpacing: 6, children: <Widget>[
                  for (final String k in <String>['PASS', 'FAIL', 'BLOCKED', 'NOT RUN', 'EXPERIMENTAL'])
                    if (totals[k] != null)
                      Row(mainAxisSize: MainAxisSize.min, children: <Widget>[
                        Icon(styleFor(p, k).$2, size: 16, color: styleFor(p, k).$1),
                        const SizedBox(width: 4),
                        Text('${totals[k]} $k'),
                      ]),
                ]),
                const SizedBox(height: 10),
                Text(
                  'A passing test is evidence for the specific behaviour it checks — not proof that '
                  'every security property holds.',
                  style: TextStyle(color: p.textSecondary, fontSize: 12),
                ),
              ]),
            ),
          ),
          const SizedBox(height: 12),
          for (final Map<String, dynamic> s in suites)
            Padding(
              padding: const EdgeInsets.only(bottom: 10),
              child: Card(
                child: ExpansionTile(
                  leading: Icon(styleFor(p, '${s['status']}').$2, color: styleFor(p, '${s['status']}').$1),
                  title: Text('${s['name']}', style: const TextStyle(fontWeight: FontWeight.w600)),
                  subtitle: Text(
                    '${s['status']} · ${s['passed'] ?? 0}/${s['total'] ?? 0} passed'
                    '${s['duration_s'] != null ? ' · ${s['duration_s']} s' : ''}',
                    style: TextStyle(color: p.textSecondary, fontSize: 12),
                  ),
                  childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
                  children: <Widget>[
                    if (s['description'] != null)
                      Align(
                        alignment: Alignment.centerLeft,
                        child: Text('${s['description']}', style: TextStyle(color: p.textSecondary, fontSize: 12.5)),
                      ),
                    if (s['command'] != null)
                      Padding(
                        padding: const EdgeInsets.only(top: 6),
                        child: SelectableText('\$ ${s['command']}',
                            style: TextStyle(fontFamily: 'monospace', fontSize: 12, color: p.textFaint)),
                      ),
                    for (final Object? t in (s['tests'] as List<Object?>? ?? <Object?>[]).take(400))
                      if (t is Map<String, dynamic>)
                        ListTile(
                          dense: true,
                          contentPadding: EdgeInsets.zero,
                          leading: Icon(styleFor(p, '${t['status']}').$2, size: 16,
                              color: styleFor(p, '${t['status']}').$1),
                          title: Text('${t['name']}', style: const TextStyle(fontSize: 12.5)),
                          subtitle: t['details'] == null
                              ? null
                              : Text('${t['details']}', maxLines: 4, overflow: TextOverflow.ellipsis,
                                  style: TextStyle(color: p.danger, fontSize: 11.5)),
                        ),
                  ],
                ),
              ),
            ),
        ]),
      ),
    );
  }
}
