/// Conversation view.
library;

import 'dart:async';

import 'package:flutter/material.dart';

import '../../crypto/session.dart';
import '../../domain/session_manager.dart';
import '../theme.dart';
import '../widgets/verification_badge.dart';
import 'verification_screen.dart';

class ConversationScreen extends StatefulWidget {
  const ConversationScreen({
    required this.manager,
    required this.peerDeviceId,
    super.key,
  });

  final SessionManager manager;
  final String peerDeviceId;

  @override
  State<ConversationScreen> createState() => _ConversationScreenState();
}

class _ConversationScreenState extends State<ConversationScreen> {
  final TextEditingController _input = TextEditingController();
  final ScrollController _scroll = ScrollController();
  StreamSubscription<void>? _changes;
  bool _sending = false;

  Conversation? get _conversation =>
      widget.manager.conversations[widget.peerDeviceId];

  @override
  void initState() {
    super.initState();
    _changes = widget.manager.changes.listen((_) {
      if (mounted) {
        setState(() {});
        _scrollToBottom();
      }
    });
  }

  void _scrollToBottom() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scroll.hasClients) {
        _scroll.jumpTo(_scroll.position.maxScrollExtent);
      }
    });
  }

  Future<void> _send() async {
    final String text = _input.text.trim();
    if (text.isEmpty || _sending) return;
    setState(() => _sending = true);
    try {
      await widget.manager.send(widget.peerDeviceId, text);
      _input.clear();
      _scrollToBottom();
    } catch (_) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Could not send \u2014 message not delivered')),
        );
      }
    } finally {
      if (mounted) setState(() => _sending = false);
    }
  }

  void _openVerification() => Navigator.push(
        context,
        MaterialPageRoute<void>(
          builder: (_) => VerificationScreen(
            manager: widget.manager,
            peerDeviceId: widget.peerDeviceId,
          ),
        ),
      );

  @override
  void dispose() {
    _input.dispose();
    _scroll.dispose();
    unawaited(_changes?.cancel());
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final Conversation? c = _conversation;
    if (c == null) {
      return const Scaffold(body: Center(child: Text('Session not found')));
    }

    return Scaffold(
      appBar: AppBar(
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            Text(widget.peerDeviceId, style: const TextStyle(fontSize: 15)),
            const Text('encrypted \u00b7 keys never leave this device',
                style: TextStyle(color: HeloColors.textFaint, fontSize: 10)),
          ],
        ),
        actions: <Widget>[
          Padding(
            padding: const EdgeInsets.only(right: 8),
            child: Center(
              child: GestureDetector(
                onTap: _openVerification,
                child: VerificationBadge(
                    status: c.session.verification, compact: true),
              ),
            ),
          ),
        ],
      ),
      body: Column(
        children: <Widget>[
          if (c.warning == ConversationWarning.identityChanged)
            IdentityChangedBanner(onVerify: _openVerification)
          else if (c.warning == ConversationWarning.weakenedHandshake)
            const DowngradeBanner()
          else if (c.session.verification == VerificationStatus.unverified)
            _UnverifiedHint(onVerify: _openVerification),
          Expanded(
            child: c.messages.isEmpty
                ? const Center(
                    child: Text('No messages yet',
                        style: TextStyle(
                            color: HeloColors.textFaint, fontSize: 12)),
                  )
                : ListView.builder(
                    controller: _scroll,
                    padding: const EdgeInsets.all(12),
                    itemCount: c.messages.length,
                    itemBuilder: (BuildContext ctx, int i) =>
                        _Bubble(message: c.messages[i]),
                  ),
          ),
          _Composer(
            controller: _input,
            sending: _sending,
            onSend: _send,
          ),
        ],
      ),
    );
  }
}

class _UnverifiedHint extends StatelessWidget {
  const _UnverifiedHint({required this.onVerify});
  final VoidCallback onVerify;

  @override
  Widget build(BuildContext context) => Container(
        width: double.infinity,
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        color: HeloColors.surface,
        child: Row(
          children: <Widget>[
            const Expanded(
              child: Text(
                'Messages are encrypted, but this contact\u2019s identity is not '
                'verified. Encryption alone does not prove who you are talking to.',
                style: TextStyle(color: HeloColors.textFaint, fontSize: 11),
              ),
            ),
            TextButton(onPressed: onVerify, child: const Text('Verify')),
          ],
        ),
      );
}

class _Bubble extends StatelessWidget {
  const _Bubble({required this.message});
  final ChatMessage message;

  @override
  Widget build(BuildContext context) {
    final bool out = message.outgoing;
    return Align(
      alignment: out ? Alignment.centerRight : Alignment.centerLeft,
      child: Container(
        margin: const EdgeInsets.symmetric(vertical: 4),
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 9),
        constraints: BoxConstraints(
            maxWidth: MediaQuery.of(context).size.width * 0.75),
        decoration: BoxDecoration(
          color: out ? HeloColors.bubbleOut : HeloColors.bubbleIn,
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: HeloColors.border),
        ),
        child: Column(
          crossAxisAlignment:
              out ? CrossAxisAlignment.end : CrossAxisAlignment.start,
          children: <Widget>[
            Text(message.body, style: const TextStyle(fontSize: 13.5)),
            const SizedBox(height: 3),
            Text(
              '${message.timestamp.hour.toString().padLeft(2, '0')}:'
              '${message.timestamp.minute.toString().padLeft(2, '0')}'
              '${out && message.delivered ? '  \u2713' : ''}',
              style:
                  const TextStyle(color: HeloColors.textFaint, fontSize: 9.5),
            ),
          ],
        ),
      ),
    );
  }
}

class _Composer extends StatelessWidget {
  const _Composer({
    required this.controller,
    required this.sending,
    required this.onSend,
  });

  final TextEditingController controller;
  final bool sending;
  final VoidCallback onSend;

  @override
  Widget build(BuildContext context) => Container(
        padding: const EdgeInsets.fromLTRB(12, 8, 12, 12),
        decoration: const BoxDecoration(
          color: HeloColors.background,
          border: Border(top: BorderSide(color: HeloColors.border)),
        ),
        child: SafeArea(
          top: false,
          child: Row(
            children: <Widget>[
              Expanded(
                child: TextField(
                  controller: controller,
                  minLines: 1,
                  maxLines: 4,
                  textInputAction: TextInputAction.send,
                  onSubmitted: (_) => onSend(),
                  decoration:
                      const InputDecoration(hintText: 'encrypted message'),
                ),
              ),
              const SizedBox(width: 8),
              FilledButton(
                onPressed: sending ? null : onSend,
                style: FilledButton.styleFrom(
                  padding: const EdgeInsets.symmetric(
                      horizontal: 16, vertical: 14),
                ),
                child: const Icon(Icons.arrow_upward, size: 18),
              ),
            ],
          ),
        ),
      );
}
