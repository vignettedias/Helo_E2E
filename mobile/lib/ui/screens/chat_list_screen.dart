/// Conversation list.
library;

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../crypto/errors.dart';
import '../../data/relay_client.dart';
import '../../domain/session_manager.dart';
import '../theme.dart';
import '../widgets/verification_badge.dart';
import 'conversation_screen.dart';
import 'diagnostics_screen.dart';
import 'security_info_screen.dart';

class ChatListScreen extends StatefulWidget {
  const ChatListScreen({required this.manager, super.key});
  final SessionManager manager;

  @override
  State<ChatListScreen> createState() => _ChatListScreenState();
}

class _ChatListScreenState extends State<ChatListScreen> {
  Timer? _poll;
  StreamSubscription<void>? _changes;
  String? _status;

  @override
  void initState() {
    super.initState();
    _changes = widget.manager.changes.listen((_) {
      if (mounted) setState(() {});
    });
    // Polling stands in for the relay's SSE stream. The stream carries only a
    // wake-up signal and never message content, so polling is functionally
    // equivalent — just less timely.
    _poll = Timer.periodic(const Duration(seconds: 3), (_) => _refresh());
    unawaited(_refresh());
  }

  Future<void> _refresh() async {
    try {
      await widget.manager.receive();
      if (mounted) setState(() => _status = null);
    } on RelayException catch (e) {
      if (mounted) {
        setState(() => _status = e.isAuthFailure
            ? 'the relay no longer recognises this device — reset it in Security'
            : 'relay error (${e.code})');
      }
    } catch (_) {
      if (mounted) setState(() => _status = 'relay unreachable');
    }
  }

  Future<void> _copyDeviceId() async {
    await Clipboard.setData(ClipboardData(text: widget.manager.deviceId));
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Device id copied')),
      );
    }
  }

  Future<void> _newConversation() async {
    final String? peer = await showDialog<String>(
      context: context,
      builder: (BuildContext ctx) => const _NewConversationDialog(),
    );
    if (peer == null || peer.isEmpty) return;

    try {
      await widget.manager.startConversation(peer);
      if (!mounted) return;
      setState(() => _status = null);
      _open(peer);
    } on RelayException catch (e) {
      _showError(switch (e.code) {
        'device_not_found' => 'No device with that id is registered.',
        'device_revoked' => 'That device has been revoked by its owner.',
        'no_signed_prekey' => 'That device has not published its keys yet.',
        'rate_limited' => 'Too many key requests. Wait a moment and retry.',
        _ => 'Could not fetch that contact’s keys (${e.code}).',
      });
    } on SignatureVerificationError {
      // The relay served keys that do not verify against the contact's
      // identity. Refusing here is the protocol working, and the user should
      // know it is a security event rather than a network glitch.
      _showError('That contact’s keys failed signature verification. '
          'The session was refused.');
    } on HeloError catch (e) {
      _showError(e is InvalidStateTransitionError
          ? 'That is this device — start a conversation with someone else.'
          : 'Could not establish a session (${e.runtimeType}).');
    } catch (_) {
      _showError('Relay unreachable.');
    }
  }

  void _showError(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(context)
        .showSnackBar(SnackBar(content: Text(message)));
  }

  void _open(String peer) => Navigator.push(
        context,
        MaterialPageRoute<void>(
          builder: (_) => ConversationScreen(
            manager: widget.manager,
            peerDeviceId: peer,
          ),
        ),
      );

  @override
  void dispose() {
    _poll?.cancel();
    unawaited(_changes?.cancel());
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final List<Conversation> conversations = widget.manager.conversations.values
        .toList()
      ..sort((Conversation a, Conversation b) =>
          _lastActivity(b).compareTo(_lastActivity(a)));

    return Scaffold(
      appBar: AppBar(
        title: const Row(
          children: <Widget>[
            Icon(Icons.lock_outline, size: 18, color: HeloColors.accent),
            SizedBox(width: 8),
            Text('helo'),
          ],
        ),
        actions: <Widget>[
          IconButton(
            icon: const Icon(Icons.monitor_heart_outlined, size: 20),
            tooltip: 'Diagnostics',
            onPressed: () => Navigator.push(
              context,
              MaterialPageRoute<void>(
                builder: (_) => DiagnosticsScreen(manager: widget.manager),
              ),
            ),
          ),
          IconButton(
            icon: const Icon(Icons.shield_outlined, size: 20),
            tooltip: 'Security',
            onPressed: () => Navigator.push(
              context,
              MaterialPageRoute<void>(
                builder: (_) => SecurityInfoScreen(manager: widget.manager),
              ),
            ),
          ),
        ],
        bottom: _status == null
            ? null
            : PreferredSize(
                preferredSize: const Size.fromHeight(24),
                child: Container(
                  width: double.infinity,
                  padding: const EdgeInsets.symmetric(vertical: 5),
                  color: HeloColors.warning.withValues(alpha: 0.15),
                  child: Text(
                    _status!,
                    textAlign: TextAlign.center,
                    style: const TextStyle(
                        color: HeloColors.warning, fontSize: 11),
                  ),
                ),
              ),
      ),
      floatingActionButton: FloatingActionButton.extended(
        backgroundColor: HeloColors.accent,
        foregroundColor: const Color(0xFF04120C),
        onPressed: _newConversation,
        icon: const Icon(Icons.add),
        label: const Text('New chat'),
      ),
      body: RefreshIndicator(
        onRefresh: _refresh,
        child: ListView(
          padding: const EdgeInsets.only(bottom: 96),
          children: <Widget>[
            _IdentityCard(
              username: widget.manager.username,
              deviceId: widget.manager.deviceId,
              onCopy: _copyDeviceId,
            ),
            if (conversations.isEmpty)
              const _EmptyState()
            else ...<Widget>[
              const Padding(
                padding: EdgeInsets.fromLTRB(16, 18, 16, 6),
                child: Text('CONVERSATIONS',
                    style: TextStyle(
                        fontSize: 10.5,
                        color: HeloColors.textFaint,
                        letterSpacing: 1.5)),
              ),
              for (final Conversation c in conversations) ...<Widget>[
                _ConversationTile(
                    conversation: c, onTap: () => _open(c.peerDeviceId)),
                const Divider(height: 1, indent: 72),
              ],
            ],
          ],
        ),
      ),
    );
  }

  static DateTime _lastActivity(Conversation c) => c.messages.isEmpty
      ? DateTime.fromMillisecondsSinceEpoch(0)
      : c.messages.last.timestamp;
}

class _IdentityCard extends StatelessWidget {
  const _IdentityCard({
    required this.username,
    required this.deviceId,
    required this.onCopy,
  });

  final String? username;
  final String deviceId;
  final VoidCallback onCopy;

  @override
  Widget build(BuildContext context) => Container(
        margin: const EdgeInsets.fromLTRB(16, 12, 16, 4),
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          color: HeloColors.surface,
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: HeloColors.border),
        ),
        child: Row(
          children: <Widget>[
            _Avatar(label: username ?? deviceId, color: HeloColors.accent),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: <Widget>[
                  Text(username ?? 'this device',
                      style: const TextStyle(
                          fontSize: 14, fontWeight: FontWeight.w600)),
                  const SizedBox(height: 3),
                  SelectableText(deviceId,
                      style: const TextStyle(
                          color: HeloColors.textSecondary, fontSize: 12)),
                  const SizedBox(height: 4),
                  const Text(
                    'Share this device id so contacts can reach you.',
                    style:
                        TextStyle(color: HeloColors.textFaint, fontSize: 10.5),
                  ),
                ],
              ),
            ),
            IconButton(
              tooltip: 'Copy device id',
              icon: const Icon(Icons.copy_rounded, size: 18),
              onPressed: onCopy,
            ),
          ],
        ),
      );
}

class _ConversationTile extends StatelessWidget {
  const _ConversationTile({required this.conversation, required this.onTap});
  final Conversation conversation;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final Conversation c = conversation;
    final ChatMessage? last = c.messages.isEmpty ? null : c.messages.last;
    final String preview = last == null
        ? 'no messages yet'
        : '${last.outgoing ? 'you: ' : ''}${last.body}';

    return ListTile(
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      leading: _Avatar(
        label: c.peerDeviceId.replaceFirst('device-', ''),
        color: c.warning == ConversationWarning.identityChanged
            ? HeloColors.danger
            : HeloColors.textSecondary,
      ),
      title: Text(c.peerDeviceId, style: const TextStyle(fontSize: 14)),
      subtitle: Padding(
        padding: const EdgeInsets.only(top: 4),
        child: Text(
          preview,
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
          style: const TextStyle(color: HeloColors.textFaint, fontSize: 12),
        ),
      ),
      trailing:
          VerificationBadge(status: c.session.verification, compact: true),
      onTap: onTap,
    );
  }
}

class _Avatar extends StatelessWidget {
  const _Avatar({required this.label, required this.color});
  final String label;
  final Color color;

  @override
  Widget build(BuildContext context) => CircleAvatar(
        radius: 20,
        backgroundColor: color.withValues(alpha: 0.14),
        child: Text(
          label.isEmpty ? '?' : label.substring(0, 1).toUpperCase(),
          style: TextStyle(color: color, fontWeight: FontWeight.w700),
        ),
      );
}

class _NewConversationDialog extends StatefulWidget {
  const _NewConversationDialog();

  @override
  State<_NewConversationDialog> createState() => _NewConversationDialogState();
}

class _NewConversationDialogState extends State<_NewConversationDialog> {
  final TextEditingController _controller = TextEditingController();

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  void _submit() => Navigator.pop(context, _controller.text.trim());

  @override
  Widget build(BuildContext context) => AlertDialog(
        backgroundColor: HeloColors.surface,
        title: const Text('New conversation', style: TextStyle(fontSize: 16)),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: <Widget>[
            TextField(
              controller: _controller,
              autofocus: true,
              autocorrect: false,
              onSubmitted: (_) => _submit(),
              decoration: const InputDecoration(
                  hintText: 'contact’s device id, e.g. device-3fa9c1d2e07b'),
            ),
            const SizedBox(height: 12),
            const Text(
              'A session will be established even if this contact is offline. '
              'Their identity is not yet verified — compare safety numbers '
              'in person before trusting it.',
              style: TextStyle(color: HeloColors.textFaint, fontSize: 11),
            ),
          ],
        ),
        actions: <Widget>[
          TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('Cancel')),
          FilledButton(onPressed: _submit, child: const Text('Start')),
        ],
      );
}

class _EmptyState extends StatelessWidget {
  const _EmptyState();

  @override
  Widget build(BuildContext context) => const Padding(
        padding: EdgeInsets.fromLTRB(32, 56, 32, 32),
        child: Column(
          children: <Widget>[
            Icon(Icons.forum_outlined, size: 36, color: HeloColors.textFaint),
            SizedBox(height: 14),
            Text('No conversations yet',
                style: TextStyle(color: HeloColors.textSecondary)),
            SizedBox(height: 8),
            Text(
              'Tap New chat and paste a contact’s device id. They do not '
              'need to be online — their published prekeys are enough to '
              'start an encrypted session.',
              textAlign: TextAlign.center,
              style: TextStyle(color: HeloColors.textFaint, fontSize: 12),
            ),
          ],
        ),
      );
}
