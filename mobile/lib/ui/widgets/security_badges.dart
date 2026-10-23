/// Security-state indicators. Each state has an icon AND a word, never colour
/// alone, and each is derived from real state (session handshake, device
/// pins) — never from "the message was sent".
library;

import 'package:flutter/material.dart';

import '../../domain/models.dart';
import '../theme.dart';

enum TrustState { verified, unverified, keyChanged }

class TrustBadge extends StatelessWidget {
  const TrustBadge({required this.state, this.compact = false, super.key});
  final TrustState state;
  final bool compact;

  @override
  Widget build(BuildContext context) {
    final HeloPalette p = HeloPalette.of(context);
    final (Color color, IconData icon, String label) = switch (state) {
      TrustState.verified => (p.success, Icons.verified_user_outlined, 'Verified'),
      TrustState.unverified => (p.textSecondary, Icons.shield_outlined, 'Not verified'),
      TrustState.keyChanged => (p.danger, Icons.gpp_bad_outlined, 'Key changed'),
    };
    return _Chip(color: color, icon: icon, label: label, compact: compact);
  }
}

/// Which handshake protects the conversation's sessions.
class HandshakeBadge extends StatelessWidget {
  const HandshakeBadge({required this.kex, this.compact = false, super.key});

  /// Session establishment ids in use (`pqxdh-mlkem768`, `x3dh`). Empty until
  /// a session exists.
  final Set<String> kex;
  final bool compact;

  @override
  Widget build(BuildContext context) {
    final HeloPalette p = HeloPalette.of(context);
    if (kex.isEmpty) return const SizedBox.shrink();
    if (kex.contains('x3dh')) {
      return _Chip(color: p.warning, icon: Icons.warning_amber_rounded,
          label: compact ? 'Classical' : 'Classical X3DH', compact: compact);
    }
    return _Chip(color: p.info, icon: Icons.lock_outline,
        label: compact ? 'PQ hybrid' : 'PQXDH hybrid', compact: compact);
  }
}

class _Chip extends StatelessWidget {
  const _Chip({required this.color, required this.icon, required this.label, required this.compact});
  final Color color;
  final IconData icon;
  final String label;
  final bool compact;

  @override
  Widget build(BuildContext context) => Container(
        padding: EdgeInsets.symmetric(horizontal: compact ? 6 : 8, vertical: compact ? 2 : 4),
        decoration: BoxDecoration(
          color: color.withValues(alpha: 0.12),
          borderRadius: BorderRadius.circular(4),
          border: Border.all(color: color.withValues(alpha: 0.4)),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: <Widget>[
            Icon(icon, size: compact ? 12 : 14, color: color),
            const SizedBox(width: 4),
            Text(label,
                style: TextStyle(
                    color: color, fontSize: compact ? 10.5 : 11.5, fontWeight: FontWeight.w600)),
          ],
        ),
      );
}

/// Delivery state of an outgoing message. Tooltips spell out what each tick
/// does and does not prove.
class StatusTicks extends StatelessWidget {
  const StatusTicks({required this.status, this.size = 14, super.key});
  final MessageStatus status;
  final double size;

  @override
  Widget build(BuildContext context) {
    final HeloPalette p = HeloPalette.of(context);
    final (IconData icon, Color color, String tip) = switch (status) {
      MessageStatus.pending => (Icons.schedule_rounded, p.textFaint, 'Waiting for the relay'),
      MessageStatus.sent => (Icons.done_rounded, p.textFaint,
          'Accepted by the relay (not proof of delivery)'),
      MessageStatus.delivered => (Icons.done_all_rounded, p.textFaint,
          'Decrypted by the recipient\'s device'),
      MessageStatus.read => (Icons.done_all_rounded, p.accent, 'Read'),
      MessageStatus.failed => (Icons.error_outline_rounded, p.danger, 'Not sent'),
    };
    return Tooltip(message: tip, child: Icon(icon, size: size, color: color));
  }
}
