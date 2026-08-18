/// Security and privacy information.
///
/// This screen states limitations as prominently as capabilities. Users make
/// real safety decisions based on what a messenger claims; overstating
/// protection is itself a harm.
library;

import 'package:flutter/material.dart';

import '../../domain/session_manager.dart';
import '../../storage/crypto_storage.dart';
import '../theme.dart';

class SecurityInfoScreen extends StatelessWidget {
  const SecurityInfoScreen({required this.manager, super.key});
  final SessionManager manager;

  @override
  Widget build(BuildContext context) {
    final StorageBacking backing = manager.storage.backing;

    return Scaffold(
      appBar: AppBar(title: const Text('Security')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: <Widget>[
          const _Section(
            title: 'What Helo protects',
            tone: _Tone.good,
            body:
                'Message content, end to end. Messages are encrypted on this '
                'device with keys that never leave it. The server relays '
                'ciphertext and cannot read it, and neither can anyone who '
                'compromises the server or the network.\n\n'
                'Every message uses a fresh key. Old messages you have already '
                'received cannot be decrypted even by someone who later takes '
                'full control of this device.',
          ),
          const _Section(
            title: 'What Helo does NOT protect',
            tone: _Tone.bad,
            body:
                'Metadata. The server can see who you talk to, when, how '
                'often, and how long each message is. It cannot see what you '
                'say. For some people, who they talk to is the sensitive part '
                '\u2014 Helo does not hide it.\n\n'
                'This device. If someone installs malware on your phone or '
                'unlocks it, they read your messages directly. No encryption '
                'prevents that.\n\n'
                'The other person. Anything you send can be screenshotted, '
                'saved, or forwarded by the recipient.',
          ),
          const _Section(
            title: 'Not quantum-resistant',
            tone: _Tone.warn,
            body:
                'Helo uses classical elliptic-curve cryptography (X25519). A '
                'sufficiently large quantum computer, which does not exist '
                'today, would break it retroactively against recorded traffic. '
                'A post-quantum upgrade is designed for but not implemented, '
                'and no post-quantum protection is claimed.',
          ),
          _Section(
            title: 'Where your keys are stored',
            tone: _Tone.info,
            body: backing.description,
          ),
          const _Section(
            title: 'Verification matters',
            tone: _Tone.warn,
            body:
                'Encryption proves your messages are unreadable in transit. It '
                'does NOT prove who is at the other end. The first time you '
                'contact someone, the app trusts the key it is given.\n\n'
                'Compare safety numbers in person to close that gap. Until you '
                'do, an attacker who controls the server could in principle '
                'have placed themselves in the middle from the very start.',
          ),
          const _Section(
            title: 'This is not audited software',
            tone: _Tone.bad,
            body:
                'Helo is a research and portfolio implementation. It has not '
                'been independently security-audited and should not be used to '
                'protect communications where real harm could result from '
                'failure.',
          ),
          const SizedBox(height: 8),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(14),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: <Widget>[
                  const Text('Reset all key material',
                      style: TextStyle(
                          fontSize: 13, fontWeight: FontWeight.w600)),
                  const SizedBox(height: 6),
                  const Text(
                    'Destroys your identity key, all sessions, and all message '
                    'history on this device. This cannot be undone, and your '
                    'contacts will see an identity-change warning.',
                    style: TextStyle(
                        color: HeloColors.textFaint, fontSize: 11.5),
                  ),
                  const SizedBox(height: 10),
                  OutlinedButton(
                    style: OutlinedButton.styleFrom(
                      foregroundColor: HeloColors.danger,
                      side: const BorderSide(color: HeloColors.danger),
                    ),
                    onPressed: () => _confirmReset(context),
                    child: const Text('Reset'),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Future<void> _confirmReset(BuildContext context) async {
    final bool? confirmed = await showDialog<bool>(
      context: context,
      builder: (BuildContext ctx) => AlertDialog(
        backgroundColor: HeloColors.surface,
        title: const Text('Destroy all keys?', style: TextStyle(fontSize: 16)),
        content: const Text(
          'Your message history will become permanently unreadable. There is '
          'no recovery \u2014 not by us, not by resetting your password.',
          style: TextStyle(fontSize: 12.5),
        ),
        actions: <Widget>[
          TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('Cancel')),
          FilledButton(
            style: FilledButton.styleFrom(
                backgroundColor: HeloColors.danger,
                foregroundColor: Colors.white),
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('Destroy'),
          ),
        ],
      ),
    );

    if (confirmed ?? false) {
      await manager.resetEverything();
      if (context.mounted) Navigator.pop(context);
    }
  }
}

enum _Tone { good, bad, warn, info }

class _Section extends StatelessWidget {
  const _Section({required this.title, required this.body, required this.tone});
  final String title;
  final String body;
  final _Tone tone;

  @override
  Widget build(BuildContext context) {
    final (Color color, IconData icon) = switch (tone) {
      _Tone.good => (HeloColors.accent, Icons.check_circle_outline),
      _Tone.bad => (HeloColors.danger, Icons.cancel_outlined),
      _Tone.warn => (HeloColors.warning, Icons.warning_amber_outlined),
      _Tone.info => (HeloColors.textSecondary, Icons.info_outline),
    };

    return Container(
      margin: const EdgeInsets.only(bottom: 14),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: HeloColors.surface,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: color.withValues(alpha: 0.3)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          Row(
            children: <Widget>[
              Icon(icon, size: 16, color: color),
              const SizedBox(width: 8),
              Expanded(
                child: Text(title,
                    style: TextStyle(
                        fontSize: 13,
                        fontWeight: FontWeight.w700,
                        color: color)),
              ),
            ],
          ),
          const SizedBox(height: 10),
          Text(body,
              style: const TextStyle(
                  color: HeloColors.textSecondary,
                  fontSize: 11.5,
                  height: 1.55)),
        ],
      ),
    );
  }
}
