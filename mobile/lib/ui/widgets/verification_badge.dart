/// Verification state indicator.
///
/// Deliberately NOT colour-only: each state carries an icon and a word. A user
/// who cannot distinguish the colours must still be able to tell "verified"
/// from "identity changed", because that is exactly the distinction an
/// attacker benefits from blurring.
library;

import 'package:flutter/material.dart';

import '../../crypto/session.dart';
import '../theme.dart';

class VerificationBadge extends StatelessWidget {
  const VerificationBadge({required this.status, this.compact = false, super.key});

  final VerificationStatus status;
  final bool compact;

  @override
  Widget build(BuildContext context) {
    final (Color color, IconData icon, String label) = switch (status) {
      VerificationStatus.verified => (
          HeloColors.accent,
          Icons.verified_user_outlined,
          'VERIFIED'
        ),
      VerificationStatus.unverified => (
          HeloColors.warning,
          Icons.help_outline,
          'UNVERIFIED'
        ),
      VerificationStatus.identityChanged => (
          HeloColors.danger,
          Icons.gpp_maybe_outlined,
          'IDENTITY CHANGED'
        ),
    };

    return Container(
      padding: EdgeInsets.symmetric(
          horizontal: compact ? 6 : 10, vertical: compact ? 3 : 6),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(6),
        border: Border.all(color: color.withValues(alpha: 0.45)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: <Widget>[
          Icon(icon, size: compact ? 12 : 15, color: color),
          const SizedBox(width: 6),
          Text(
            label,
            style: TextStyle(
              color: color,
              fontSize: compact ? 10 : 11,
              fontWeight: FontWeight.w700,
              letterSpacing: 0.6,
            ),
          ),
        ],
      ),
    );
  }
}

/// Banner shown when a session used the weaker three-DH handshake.
class DowngradeBanner extends StatelessWidget {
  const DowngradeBanner({super.key});

  @override
  Widget build(BuildContext context) => Container(
        width: double.infinity,
        padding: const EdgeInsets.all(12),
        color: HeloColors.warning.withValues(alpha: 0.12),
        child: const Row(
          children: <Widget>[
            Icon(Icons.info_outline, size: 16, color: HeloColors.warning),
            SizedBox(width: 10),
            Expanded(
              child: Text(
                'This session used a reduced handshake: the contact had no '
                'one-time prekeys left. Forward secrecy for the first message '
                'is weaker. This can be caused by an attacker draining them.',
                style: TextStyle(color: HeloColors.warning, fontSize: 11.5),
              ),
            ),
          ],
        ),
      );
}

/// Banner shown when a peer's identity key changes. Cannot be dismissed by
/// simply marking the contact verified — the user must re-verify out of band.
class IdentityChangedBanner extends StatelessWidget {
  const IdentityChangedBanner({required this.onVerify, super.key});
  final VoidCallback onVerify;

  @override
  Widget build(BuildContext context) => Container(
        width: double.infinity,
        padding: const EdgeInsets.all(12),
        color: HeloColors.danger.withValues(alpha: 0.14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            const Row(
              children: <Widget>[
                Icon(Icons.gpp_maybe_outlined,
                    size: 16, color: HeloColors.danger),
                SizedBox(width: 10),
                Expanded(
                  child: Text(
                    'This contact\u2019s identity key has changed. This happens '
                    'when they reinstall or switch device \u2014 but it is also '
                    'what an interception attempt looks like. Messages are '
                    'being rejected until you re-verify in person.',
                    style:
                        TextStyle(color: HeloColors.danger, fontSize: 11.5),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            Align(
              alignment: Alignment.centerRight,
              child: TextButton(
                onPressed: onVerify,
                child: const Text('Compare safety number'),
              ),
            ),
          ],
        ),
      );
}
