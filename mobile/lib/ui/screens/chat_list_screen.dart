/// Conversation list.
library;

import 'dart:async';

import 'package:flutter/material.dart';

import '../../crypto/session.dart';
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
    } catch (_) {
      if (mounted) setState(() => _status = 'relay unreachable');
    }
  }

  Future<void> _newConversation() async {
    final TextEditingController controller = TextEditingController();
    final String? peer = await showDialog<String>(
      context: context,
      builder: (BuildContext ctx) => AlertDialog(
        backgroundColor: HeloColors.surface,
        title: const Text('New conversation', style: TextStyle(fontSize: 16)),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: <Widget>[
            TextField(
              controller: controller,
              autocorrect: false,
              decoration:
                  const InputDecoration(hintText: 'peer device id'),
            ),
            const SizedBox(height: 12),
            const Text(
              'A session will be established even if this contact is offline. '
              'Their identity is not yet verified \u2014 compare safety numbers '
              'in person before trusting it.',
              style: TextStyle(color: HeloColors.textFaint, fontSize: 11),
            ),
          ],
        ),
        actions: <Widget>[
          TextButton(
              onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
          FilledButton(
            onPressed: () => Navigator.pop(ctx, controller.text.trim()),
            child: const Text('Start'),
          ),
        ],
      ),
    );

    if (peer == null || peer.isEmpty) return;
    try {
      await widget.manager.startConversation(peer);
      if (mounted) setState(() {});
    } catch (_) {
      if (mounted) {
        setState(() => _status = 'could not fetch that contact\u2019s keys');
      }
    }
  }

  @override
  void dispose() {
    _poll?.cancel();
    unawaited(_changes?.cancel());
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final List<Conversation> conversations =
        widget.manager.conversations.values.toList();

    return Scaffold(
      appBar: AppBar(
        title: const Text('helo'),
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
                preferredSize: const Size.fromHeight(22),
                child: Container(
                  width: double.infinity,
                  padding: const EdgeInsets.symmetric(vertical: 4),
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
      floatingActionButton: FloatingActionButton(
        backgroundColor: HeloColors.accent,
        foregroundColor: const Color(0xFF04120C),
        onPressed: _newConversation,
        child: const Icon(Icons.add),
      ),
      body: conversations.isEmpty
          ? const _EmptyState()
          : RefreshIndicator(
              onRefresh: _refresh,
              child: ListView.separated(
                itemCount: conversations.length,
                separatorBuilder: (_, __) => const Divider(height: 1),
                itemBuilder: (BuildContext ctx, int i) {
                  final Conversation c = conversations[i];
                  final ChatMessage? last =
                      c.messages.isEmpty ? null : c.messages.last;
                  return ListTile(
                    title: Text(c.peerDeviceId,
                        style: const TextStyle(fontSize: 14)),
                    subtitle: Padding(
                      padding: const EdgeInsets.only(top: 4),
                      child: Text(
                        last?.body ?? 'no messages yet',
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: const TextStyle(
                            color: HeloColors.textFaint, fontSize: 12),
                      ),
                    ),
                    trailing: VerificationBadge(
                        status: c.session.verification, compact: true),
                    onTap: () => Navigator.push(
                      context,
                      MaterialPageRoute<void>(
                        builder: (_) => ConversationScreen(
                          manager: widget.manager,
                          peerDeviceId: c.peerDeviceId,
                        ),
                      ),
                    ),
                  );
                },
              ),
            ),
    );
  }
}

class _EmptyState extends StatelessWidget {
  const _EmptyState();

  @override
  Widget build(BuildContext context) => const Center(
        child: Padding(
          padding: EdgeInsets.all(32),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: <Widget>[
              Icon(Icons.forum_outlined, size: 36, color: HeloColors.textFaint),
              SizedBox(height: 14),
              Text('No conversations yet',
                  style: TextStyle(color: HeloColors.textSecondary)),
              SizedBox(height: 8),
              Text(
                'Start one with a contact\u2019s device id. They do not need to '
                'be online.',
                textAlign: TextAlign.center,
                style: TextStyle(color: HeloColors.textFaint, fontSize: 12),
              ),
            ],
          ),
        ),
      );
}
