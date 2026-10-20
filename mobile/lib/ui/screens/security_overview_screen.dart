/// What HELO protects, and what it does not. Limitations are stated as
/// prominently as capabilities: users make real safety decisions on the
/// basis of what a messenger claims, and overstating protection is a harm.
library;

import 'package:flutter/material.dart';

import '../theme.dart';

class SecurityOverviewScreen extends StatelessWidget {
  const SecurityOverviewScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('What HELO protects')),
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 720),
          child: ListView(padding: const EdgeInsets.all(16), children: const <Widget>[
            _Item(_Tone.good, 'Message content, end to end',
                'Messages, reactions, edits, receipts, typing indicators, profiles and files are '
                'encrypted on your device. The relay carries ciphertext and never holds a key that '
                'could decrypt it — verified by tests that inspect the relay\'s database.'),
            _Item(_Tone.good, 'Old messages after a device compromise',
                'Every message uses a fresh key that is deleted after use (forward secrecy). Messages '
                'already received cannot be decrypted later from a stolen copy of the session state.'),
            _Item(_Tone.warn, 'Post-quantum protection — for session setup only',
                'New sessions use a hybrid handshake (X25519 + ML-KEM-768), so a future quantum '
                'computer cannot recover the session key from recorded traffic. The ratchet steps '
                'after it are classical. This hybrid mode is experimental and has not been formally '
                'analysed or independently audited.'),
            _Item(_Tone.bad, 'Metadata',
                'The relay sees which accounts and devices talk, when, how often, and padded message '
                'sizes. It also sees your IP address. HELO pads messages to hide exact length, but '
                'it does not hide who talks to whom or when.'),
            _Item(_Tone.bad, 'Your device and the other person',
                'Malware on a phone, or someone who unlocks it, reads messages directly. Recipients '
                'can screenshot or copy anything — disappearing messages cannot prevent that.'),
            _Item(_Tone.warn, 'Who you are talking to',
                'Encryption proves you share keys with someone; it does not prove who. The first time '
                'you contact someone the app trusts the key the relay provides. Compare safety numbers '
                'in person to close that gap.'),
            _Item(_Tone.info, 'Key storage',
                'On Android and iOS, keys are encrypted under a key held by the platform keystore. In '
                'the browser build, keys are encrypted under a key held by the same browser — much '
                'weaker, and suitable for demonstration only.'),
            _Item(_Tone.bad, 'Not audited',
                'HELO is a research implementation. Do not rely on it where failure could cause harm.'),
          ]),
        ),
      ),
    );
  }
}

enum _Tone { good, warn, bad, info }

class _Item extends StatelessWidget {
  const _Item(this.tone, this.title, this.body);
  final _Tone tone;
  final String title;
  final String body;

  @override
  Widget build(BuildContext context) {
    final HeloPalette p = HeloPalette.of(context);
    final (Color color, IconData icon) = switch (tone) {
      _Tone.good => (p.success, Icons.check_circle_outline_rounded),
      _Tone.warn => (p.warning, Icons.warning_amber_rounded),
      _Tone.bad => (p.danger, Icons.cancel_outlined),
      _Tone.info => (p.info, Icons.info_outline_rounded),
    };
    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: p.surface,
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: color.withValues(alpha: 0.35)),
      ),
      child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: <Widget>[
        Icon(icon, color: color, size: 20),
        const SizedBox(width: 12),
        Expanded(
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: <Widget>[
            Text(title, style: TextStyle(fontWeight: FontWeight.w700, color: color)),
            const SizedBox(height: 6),
            Text(body, style: TextStyle(color: p.textSecondary, height: 1.5, fontSize: 13)),
          ]),
        ),
      ]),
    );
  }
}
