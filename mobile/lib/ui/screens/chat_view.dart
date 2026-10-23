import 'dart:async';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../data/relay_client.dart';
import '../../domain/messenger.dart';
import '../../domain/models.dart';
import '../../protocol/payload.dart';
import '../format.dart';
import '../theme.dart';
import '../widgets/avatar.dart';
import '../widgets/message_bubble.dart';
import '../widgets/voice_recorder.dart';
import '../deck_state.dart';
import '../widgets/security_badges.dart';

const List<String> quickReactions = <String>['👍', '❤️', '😂', '😮', '😢', '🙏'];

TrustState trustOf(Messenger m, Conversation c) => m.hasConflict(c)
    ? TrustState.keyChanged
    : (m.isVerified(c) ? TrustState.verified : TrustState.unverified);

class ChatView extends StatefulWidget {
  const ChatView({
    required this.messenger,
    required this.convId,
    required this.onOpenInfo,
    this.onBack,
    super.key,
  });

  final Messenger messenger;
  final String convId;
  final VoidCallback onOpenInfo;
  final VoidCallback? onBack;

  @override
  State<ChatView> createState() => _ChatViewState();
}

class _ChatViewState extends State<ChatView> {
  final TextEditingController _input = TextEditingController();
  final FocusNode _focus = FocusNode();
  final TextEditingController _search = TextEditingController();
  StreamSubscription<void>? _sub;
  Timer? _ticker;
  Timer? _typingIdle;
  bool _recording = false;
  bool _viewOnce = false;
  Presence? _presence;
  ChatMessage? _replyTo;
  ChatMessage? _editing;
  bool _searching = false;
  bool _sending = false;
  int _visible = 150;
  int _unreadAtOpen = 0;

  Messenger get _m => widget.messenger;
  Conversation? get _c => _m.conversations[widget.convId];

  @override
  void initState() {
    super.initState();
    xrayMode.addListener(_deckChanged);
    privacyBlur.addListener(_deckChanged);
    _sub = _m.changes.listen((_) {
      if (mounted) setState(() {});
    });
    _attach();
    // Re-evaluates typing indicators and presence while the chat is open.
    _ticker = Timer.periodic(const Duration(seconds: 2), (Timer t) {
      if (mounted) setState(() {});
      if (t.tick % 10 == 0) unawaited(_refreshPresence());
    });
  }

  @override
  void didUpdateWidget(ChatView old) {
    super.didUpdateWidget(old);
    if (old.convId != widget.convId) {
      _detach(old.convId);
      _replyTo = null;
      _editing = null;
      _input.clear();
      _searching = false;
      _visible = 150;
      _attach();
    }
  }

  void _attach() {
    _unreadAtOpen = _c?.unread ?? 0;
    _m.activeConversationId = widget.convId;
    unawaited(_m.markRead(widget.convId));
    _presence = null;
    unawaited(_refreshPresence());
  }

  void _detach(String convId) {
    if (_m.activeConversationId == convId) _m.activeConversationId = null;
    unawaited(_m.setTyping(convId, false));
  }

  Future<void> _refreshPresence() async {
    final Conversation? c = _c;
    if (c == null || c.isGroup) return;
    final Presence? p = await _m.presenceOf(c.peer!);
    if (mounted) setState(() => _presence = p);
  }

  void _deckChanged() {
    if (mounted) setState(() {});
  }

  @override
  void dispose() {
    xrayMode.removeListener(_deckChanged);
    privacyBlur.removeListener(_deckChanged);
    _detach(widget.convId);
    _sub?.cancel();
    _ticker?.cancel();
    _typingIdle?.cancel();
    _input.dispose();
    _focus.dispose();
    _search.dispose();
    super.dispose();
  }

  void _toast(String text) => ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(text)));

  Future<void> _guard(Future<void> Function() action) async {
    try {
      await action();
    } on MessengerException catch (e) {
      _toast(e.message);
    } on RelayException catch (e) {
      _toast(e.isRateLimited ? 'Slow down — the relay is rate limiting.' : e.describe);
    } on Object {
      _toast('Something went wrong. Please try again.');
    }
  }

  // ------------------------------------------------------------- sending

  void _onChanged(String text) {
    if (_editing != null) return;
    unawaited(_m.setTyping(widget.convId, text.trim().isNotEmpty));
    _typingIdle?.cancel();
    _typingIdle = Timer(const Duration(seconds: 5), () => unawaited(_m.setTyping(widget.convId, false)));
  }

  Future<void> _submit() async {
    final String text = _input.text;
    if (text.trim().isEmpty || _sending) return;
    setState(() => _sending = true);
    final ChatMessage? reply = _replyTo;
    final ChatMessage? editing = _editing;
    _input.clear();
    setState(() {
      _replyTo = null;
      _editing = null;
    });
    unawaited(_m.setTyping(widget.convId, false));
    await _guard(() async {
      if (editing != null) {
        await _m.edit(widget.convId, editing.id, text);
      } else {
        await _m.sendText(widget.convId, text, replyToId: reply?.id, viewOnce: _viewOnce);
        if (mounted && _viewOnce) setState(() => _viewOnce = false);
      }
    });
    if (mounted) {
      setState(() => _sending = false);
      _focus.requestFocus();
    }
  }

  Future<void> _sendVoice(VoiceClip clip) async {
    final String stamp = DateTime.now().toIso8601String().replaceAll(RegExp(r'[^0-9]'), '').substring(0, 14);
    await _guard(() => _m.sendAttachment(
          widget.convId,
          clip.bytes,
          name: 'voice-$stamp.${clip.extension}',
          mime: clip.mime,
          voice: true,
          durationMs: clip.duration.inMilliseconds,
        ));
    if (mounted) setState(() => _recording = false);
  }

  Future<void> _attachFile({required bool image}) async {
    final FilePickerResult? picked = await FilePicker.pickFiles(
      type: image ? FileType.image : FileType.any,
      withData: true,
    );
    final PlatformFile? f = picked?.files.single;
    final Uint8List? bytes = f?.bytes;
    if (f == null || bytes == null) return;
    setState(() => _sending = true);
    await _guard(() => _m.sendAttachment(
          widget.convId,
          bytes,
          name: f.name,
          mime: _mimeFor(f.extension ?? '', image),
          caption: _input.text,
        ));
    _input.clear();
    if (mounted) setState(() => _sending = false);
  }

  static String _mimeFor(String ext, bool image) {
    const Map<String, String> known = <String, String>{
      'png': 'image/png',
      'jpg': 'image/jpeg',
      'jpeg': 'image/jpeg',
      'gif': 'image/gif',
      'webp': 'image/webp',
      'pdf': 'application/pdf',
      'txt': 'text/plain',
      'mp3': 'audio/mpeg',
      'm4a': 'audio/mp4',
      'ogg': 'audio/ogg',
      'wav': 'audio/wav',
      'mp4': 'video/mp4',
      'mov': 'video/quicktime',
      'webm': 'video/webm',
      'doc': 'application/msword',
      'zip': 'application/zip',
      'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    };
    return known[ext.toLowerCase()] ?? (image ? 'image/*' : 'application/octet-stream');
  }

  // ------------------------------------------------------------- actions

  Future<void> _actions(ChatMessage msg) async {
    final Conversation c = _c!;
    final HeloPalette p = HeloPalette.of(context);
    final bool canWrite = !(c.isGroup && c.group!.removed);
    final String? choice = await showModalBottomSheet<String>(
      context: context,
      // Up to nine rows: scroll rather than overflow on short windows.
      isScrollControlled: true,
      constraints: BoxConstraints(maxHeight: MediaQuery.sizeOf(context).height * 0.85),
      builder: (BuildContext ctx) => SafeArea(
        child: SingleChildScrollView(
          child: Column(mainAxisSize: MainAxisSize.min, children: <Widget>[
            if (!msg.deleted && canWrite)
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                  children: <Widget>[
                    for (final String e in quickReactions)
                      InkWell(
                        borderRadius: BorderRadius.circular(4),
                        onTap: () => Navigator.pop(ctx, 'react:$e'),
                        child: Container(
                          padding: const EdgeInsets.all(8),
                          decoration: BoxDecoration(
                            color: msg.reactions[_m.username] == e
                                ? p.accent.withValues(alpha: 0.2)
                                : Colors.transparent,
                            shape: BoxShape.circle,
                          ),
                          child: Text(e, style: const TextStyle(fontSize: 24)),
                        ),
                      ),
                  ],
                ),
              ),
            if (msg.status == MessageStatus.failed && msg.outgoing)
              _action(ctx, Icons.refresh_rounded, 'Retry sending', 'retry'),
            if (!msg.deleted && canWrite) _action(ctx, Icons.reply_rounded, 'Reply', 'reply'),
            if (!msg.deleted && msg.body.isNotEmpty) _action(ctx, Icons.copy_rounded, 'Copy text', 'copy'),
            if (!msg.deleted) _action(ctx, Icons.shortcut_rounded, 'Forward', 'forward'),
            if (_m.canEdit(msg) && canWrite) _action(ctx, Icons.edit_outlined, 'Edit', 'edit'),
            if (msg.outgoing && !msg.deleted)
              _action(ctx, Icons.info_outline_rounded, 'Message info', 'info'),
            _action(ctx, Icons.delete_outline_rounded, 'Delete for me', 'delete_me'),
            if (_m.canDeleteForEveryone(msg) && canWrite)
              _action(ctx, Icons.delete_forever_outlined, 'Delete for everyone', 'delete_all', danger: true),
            const SizedBox(height: 8),
          ]),
        ),
      ),
    );
    if (choice == null || !mounted) return;
    if (choice.startsWith('react:')) {
      await _guard(() => _m.react(c.id, msg.id, choice.substring(6)));
      return;
    }
    switch (choice) {
      case 'retry':
        await _guard(() => _m.retryMessage(c.id, msg.id));
      case 'reply':
        setState(() {
          _replyTo = msg;
          _editing = null;
        });
        _focus.requestFocus();
      case 'copy':
        await Clipboard.setData(ClipboardData(text: msg.body));
        _toast('Copied');
      case 'forward':
        await _forward(msg);
      case 'edit':
        setState(() {
          _editing = msg;
          _replyTo = null;
          _input.text = msg.body;
        });
        _focus.requestFocus();
      case 'info':
        await _info(msg);
      case 'delete_me':
        _m.deleteForMe(c.id, msg.id);
      case 'delete_all':
        final bool? sure = await showDialog<bool>(
          context: context,
          builder: (BuildContext ctx) => AlertDialog(
            title: const Text('Delete for everyone?'),
            content: const Text('The message is removed on every device in this chat. '
                'Recipients see "This message was deleted". This cannot be undone.'),
            actions: <Widget>[
              TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
              FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Delete')),
            ],
          ),
        );
        if (sure == true) await _guard(() => _m.deleteForEveryone(c.id, msg.id));
    }
  }

  Widget _action(BuildContext ctx, IconData icon, String label, String value, {bool danger = false}) {
    final HeloPalette p = HeloPalette.of(ctx);
    return ListTile(
      dense: true,
      leading: Icon(icon, color: danger ? p.danger : null),
      title: Text(label, style: TextStyle(color: danger ? p.danger : null)),
      onTap: () => Navigator.pop(ctx, value),
    );
  }

  Future<void> _forward(ChatMessage msg) async {
    final List<Conversation> targets =
        _m.sortedConversations().where((Conversation c) => !(c.isGroup && c.group!.removed)).toList();
    final String? to = await showDialog<String>(
      context: context,
      builder: (BuildContext ctx) => SimpleDialog(
        title: const Text('Forward to…'),
        children: <Widget>[
          for (final Conversation t in targets)
            SimpleDialogOption(
              onPressed: () => Navigator.pop(ctx, t.id),
              child: Row(children: <Widget>[
                Avatar(
                    label: _m.titleOf(t),
                    size: 30,
                    group: t.isGroup,
                    image: t.isGroup ? t.group!.avatar : _m.contacts[t.peer]?.avatar),
                const SizedBox(width: 10),
                Expanded(child: Text(_m.titleOf(t), overflow: TextOverflow.ellipsis)),
              ]),
            ),
        ],
      ),
    );
    if (to == null) return;
    await _guard(() => _m.forward(widget.convId, msg.id, to));
    _toast('Forwarded');
  }

  Future<void> _info(ChatMessage msg) async {
    final Conversation c = _c!;
    final List<String> audience = c.recipients(_m.username);
    await showDialog<void>(
      context: context,
      builder: (BuildContext ctx) => AlertDialog(
        title: const Text('Message info'),
        content: SizedBox(
          width: 360,
          child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: <Widget>[
                Text('Sent ${dayLabel(msg.sentAt)} at ${clock(msg.sentAt)}'),
                const SizedBox(height: 10),
                for (final String u in audience)
                  Padding(
                    padding: const EdgeInsets.symmetric(vertical: 3),
                    child: Row(children: <Widget>[
                      Expanded(child: Text(_m.labelOf(u))),
                      Text(msg.readBy.contains(u)
                          ? 'Read'
                          : msg.deliveredTo.contains(u)
                              ? 'Delivered'
                              : msg.status == MessageStatus.pending
                                  ? 'Waiting for relay'
                                  : 'Sent'),
                    ]),
                  ),
                const SizedBox(height: 10),
                Text(
                  '"Delivered" means a recipient device decrypted the message and said so in an '
                  'end-to-end encrypted receipt. "Sent" only means the relay accepted it.',
                  style: TextStyle(color: HeloPalette.of(ctx).textFaint, fontSize: 11.5),
                ),
              ]),
        ),
        actions: <Widget>[TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Close'))],
      ),
    );
  }

  // ---------------------------------------------------------------- build

  @override
  Widget build(BuildContext context) {
    final HeloPalette p = HeloPalette.of(context);
    final Conversation? c = _c;
    if (c == null) {
      return Center(child: Text('Conversation not found', style: TextStyle(color: p.textFaint)));
    }
    return Column(children: <Widget>[
      _header(c, p),
      ..._banners(c, p),
      Expanded(child: _messages(c, p)),
      _composer(c, p),
    ]);
  }

  String _subtitle(Conversation c) {
    final List<String> typing = _m.typingIn(c.id);
    if (typing.isNotEmpty) {
      return c.isGroup ? '${typing.map(_m.labelOf).join(', ')} typing…' : 'typing…';
    }
    if (c.isGroup) {
      if (c.group!.removed) return 'You are no longer a member';
      return c.group!.members.map(_m.labelOf).join(', ');
    }
    final Presence? pr = _presence;
    if (pr?.online ?? false) return 'online';
    if (pr?.lastSeen != null) return lastSeen(pr!.lastSeen!);
    return '@${c.peer}';
  }

  Widget _header(Conversation c, HeloPalette p) {
    final bool typing = _m.typingIn(c.id).isNotEmpty;
    // On phone widths the badges would squeeze the title to nothing, so they
    // move under it instead of sitting beside it.
    final bool narrow = MediaQuery.sizeOf(context).width < 600;
    final List<Widget> badges = <Widget>[
      HandshakeBadge(kex: _m.keyEstablishmentOf(c), compact: true),
      const SizedBox(width: 6),
      TrustBadge(state: trustOf(_m, c), compact: true),
    ];
    return Material(
      color: p.surface,
      child: Container(
        padding: const EdgeInsets.fromLTRB(8, 8, 8, 8),
        decoration: BoxDecoration(border: Border(bottom: BorderSide(color: p.border))),
        child: SafeArea(
          bottom: false,
          child: _searching
              ? Row(children: <Widget>[
                  IconButton(
                    icon: const Icon(Icons.arrow_back_rounded),
                    onPressed: () => setState(() {
                      _searching = false;
                      _search.clear();
                    }),
                  ),
                  Expanded(
                    child: TextField(
                      controller: _search,
                      autofocus: true,
                      decoration: const InputDecoration(
                          hintText: 'Search in this conversation',
                          prefixIcon: Icon(Icons.search_rounded, size: 20)),
                      onChanged: (_) => setState(() {}),
                    ),
                  ),
                ])
              : Row(children: <Widget>[
                  if (widget.onBack != null)
                    IconButton(icon: const Icon(Icons.arrow_back_rounded), onPressed: widget.onBack),
                  InkWell(
                    borderRadius: BorderRadius.circular(4),
                    onTap: widget.onOpenInfo,
                    child: Avatar(
                      label: _m.titleOf(c),
                      group: c.isGroup,
                      image: c.isGroup ? c.group!.avatar : _m.contacts[c.peer]?.avatar,
                      online: !c.isGroup && (_presence?.online ?? false),
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: InkWell(
                      onTap: widget.onOpenInfo,
                      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: <Widget>[
                        Text(_m.titleOf(c),
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 15.5)),
                        const SizedBox(height: 1),
                        Text(_subtitle(c),
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: TextStyle(color: typing ? p.accent : p.textSecondary, fontSize: 12.5)),
                        if (narrow) ...<Widget>[
                          const SizedBox(height: 4),
                          SingleChildScrollView(
                            scrollDirection: Axis.horizontal,
                            child: Row(children: badges),
                          ),
                        ],
                      ]),
                    ),
                  ),
                  if (!narrow) ...badges,
                  IconButton(
                    tooltip: xrayMode.value ? 'Crypto X-Ray: on' : 'Crypto X-Ray: show what the relay sees',
                    isSelected: xrayMode.value,
                    color: xrayMode.value ? p.info : null,
                    icon: const Icon(Icons.document_scanner_outlined),
                    onPressed: () => xrayMode.value = !xrayMode.value,
                  ),
                  IconButton(
                    tooltip: 'Search',
                    icon: const Icon(Icons.search_rounded),
                    onPressed: () => setState(() => _searching = true),
                  ),
                  IconButton(
                    tooltip: 'Details & security',
                    icon: const Icon(Icons.info_outline_rounded),
                    onPressed: widget.onOpenInfo,
                  ),
                ]),
        ),
      ),
    );
  }

  List<Widget> _banners(Conversation c, HeloPalette p) {
    final List<Widget> out = <Widget>[];
    if (_m.hasConflict(c)) {
      out.add(_banner(
          p,
          p.danger,
          Icons.gpp_bad_outlined,
          'The relay reported a different key for a device in this conversation. Messages '
              'to that device are blocked. Compare safety numbers before trusting it.',
          'Review',
          widget.onOpenInfo));
    } else if (_m.keyEstablishmentOf(c).contains('x3dh')) {
      out.add(_banner(
          p,
          p.warning,
          Icons.warning_amber_rounded,
          'A session here uses classical X3DH, without post-quantum protection — you allowed '
          'classical contacts in Settings.',
          null,
          null));
    }
    if (c.disappearingSeconds > 0) {
      out.add(_banner(
          p,
          p.info,
          Icons.timer_outlined,
          'Disappearing messages: ${timerLabel(c.disappearingSeconds)}. Recipients can still '
          'copy or screenshot them.',
          null,
          null));
    }
    return out;
  }

  Widget _banner(
          HeloPalette p, Color color, IconData icon, String text, String? action, VoidCallback? onAction) =>
      Container(
        width: double.infinity,
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
        color: color.withValues(alpha: 0.1),
        child: Row(children: <Widget>[
          Icon(icon, size: 18, color: color),
          const SizedBox(width: 10),
          Expanded(child: Text(text, style: TextStyle(color: p.textSecondary, fontSize: 12))),
          if (action != null) TextButton(onPressed: onAction, child: Text(action)),
        ]),
      );

  Widget _messages(Conversation c, HeloPalette p) {
    final String q = _search.text.trim().toLowerCase();
    List<ChatMessage> msgs = c.messages;
    if (_searching && q.isNotEmpty) {
      msgs = msgs.where((ChatMessage m) => !m.system && m.body.toLowerCase().contains(q)).toList();
      if (msgs.isEmpty) {
        return Center(child: Text('No matches', style: TextStyle(color: p.textFaint)));
      }
    }
    if (msgs.isEmpty) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(32),
          child: Column(mainAxisSize: MainAxisSize.min, children: <Widget>[
            Icon(Icons.lock_outline_rounded, size: 34, color: p.accent),
            const SizedBox(height: 12),
            Text('Messages here are end-to-end encrypted',
                style: TextStyle(color: p.textSecondary, fontWeight: FontWeight.w600)),
            const SizedBox(height: 6),
            Text(
              'Only the people in this conversation can read them — not the relay that carries them.',
              textAlign: TextAlign.center,
              style: TextStyle(color: p.textFaint, fontSize: 12.5),
            ),
          ]),
        ),
      );
    }
    final int start = msgs.length > _visible ? msgs.length - _visible : 0;
    final List<ChatMessage> shown = msgs.sublist(start);
    // The unread separator sits before the first message that was unread
    // when the conversation was opened.
    int incomingSeen = 0;
    String? firstUnreadId;
    if (_unreadAtOpen > 0 && !_searching) {
      for (final ChatMessage m in shown.reversed) {
        if (!m.outgoing && !m.system) incomingSeen += 1;
        if (incomingSeen == _unreadAtOpen) {
          firstUnreadId = m.id;
          break;
        }
      }
    }

    final List<Widget> items = <Widget>[];
    if (start > 0) {
      items.add(Center(
        child: TextButton.icon(
          onPressed: () => setState(() => _visible += 150),
          icon: const Icon(Icons.history_rounded, size: 16),
          label: const Text('Load earlier messages'),
        ),
      ));
    }
    DateTime? lastDay;
    for (int i = 0; i < shown.length; i++) {
      final ChatMessage m = shown[i];
      if (lastDay == null || !sameDay(lastDay, m.sentAt)) {
        items.add(_daySeparator(p, m.sentAt));
        lastDay = m.sentAt;
      }
      if (m.id == firstUnreadId) items.add(_unreadSeparator(p));
      final ChatMessage? prev = i > 0 ? shown[i - 1] : null;
      items.add(MessageBubble(
        key: ValueKey<String>(m.id),
        messenger: _m,
        conversation: c,
        message: m,
        onActions: _actions,
        highlight: _searching && q.isNotEmpty,
        xray: xrayMode.value,
        blur: privacyBlur.value,
        showAuthor: c.isGroup && (prev == null || prev.author != m.author || prev.system),
      ));
    }
    return ColoredBox(
      color: p.background,
      child: ListView(
        reverse: true,
        padding: const EdgeInsets.symmetric(vertical: 10),
        children: items.reversed.toList(),
      ),
    );
  }

  Widget _daySeparator(HeloPalette p, DateTime t) => Center(
        child: Container(
          margin: const EdgeInsets.symmetric(vertical: 10),
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
          decoration: BoxDecoration(
            color: p.surfaceRaised,
            borderRadius: BorderRadius.circular(4),
          ),
          child: Text(dayLabel(t), style: TextStyle(color: p.textSecondary, fontSize: 11.5)),
        ),
      );

  Widget _unreadSeparator(HeloPalette p) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 16),
        child: Row(children: <Widget>[
          Expanded(child: Divider(color: p.accent.withValues(alpha: 0.5))),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 8),
            child: Text('Unread messages',
                style: TextStyle(color: p.accent, fontSize: 11.5, fontWeight: FontWeight.w600)),
          ),
          Expanded(child: Divider(color: p.accent.withValues(alpha: 0.5))),
        ]),
      );

  Widget _composer(Conversation c, HeloPalette p) {
    if (c.isGroup && c.group!.removed) {
      return Container(
        width: double.infinity,
        padding: const EdgeInsets.all(16),
        color: p.surface,
        child: Text('You can no longer send messages to this group.',
            textAlign: TextAlign.center, style: TextStyle(color: p.textFaint)),
      );
    }
    if (!c.isGroup && (_m.contacts[c.peer]?.blocked ?? false)) {
      return Container(
        width: double.infinity,
        padding: const EdgeInsets.all(12),
        color: p.surface,
        child: Row(mainAxisAlignment: MainAxisAlignment.center, children: <Widget>[
          Text('You blocked this contact.', style: TextStyle(color: p.textFaint)),
          TextButton(onPressed: () => _guard(() => _m.unblock(c.peer!)), child: const Text('Unblock')),
        ]),
      );
    }
    final ChatMessage? quoted = _editing ?? _replyTo;
    return Container(
      decoration: BoxDecoration(
        color: p.surface,
        border: Border(top: BorderSide(color: p.border)),
      ),
      padding: const EdgeInsets.fromLTRB(8, 6, 8, 8),
      child: SafeArea(
        top: false,
        child: Column(mainAxisSize: MainAxisSize.min, children: <Widget>[
          if (quoted != null)
            Container(
              margin: const EdgeInsets.fromLTRB(4, 0, 4, 6),
              padding: const EdgeInsets.fromLTRB(10, 6, 4, 6),
              decoration: BoxDecoration(
                color: p.surfaceRaised,
                borderRadius: BorderRadius.circular(4),
                border: Border(left: BorderSide(color: p.accent, width: 3)),
              ),
              child: Row(children: <Widget>[
                Icon(_editing != null ? Icons.edit_outlined : Icons.reply_rounded, size: 16, color: p.accent),
                const SizedBox(width: 8),
                Expanded(
                  child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: <Widget>[
                    Text(_editing != null ? 'Editing message' : 'Replying to ${_m.labelOf(quoted.author)}',
                        style: TextStyle(color: p.accent, fontSize: 12, fontWeight: FontWeight.w600)),
                    Text(quoted.body.isEmpty ? 'Attachment' : quoted.body,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: TextStyle(color: p.textSecondary, fontSize: 12.5)),
                  ]),
                ),
                IconButton(
                  icon: const Icon(Icons.close_rounded, size: 18),
                  onPressed: () => setState(() {
                    if (_editing != null) _input.clear();
                    _editing = null;
                    _replyTo = null;
                  }),
                ),
              ]),
            ),
          if (_recording)
            VoiceRecorderBar(
              onDone: _sendVoice,
              onCancel: (String? reason) {
                if (mounted) setState(() => _recording = false);
                if (reason != null) _toast(reason);
              },
            )
          else
            Row(crossAxisAlignment: CrossAxisAlignment.end, children: <Widget>[
              PopupMenuButton<String>(
                tooltip: 'Attach',
                enabled: !_sending && _editing == null,
                icon: Icon(Icons.add_circle_outline_rounded, color: p.textSecondary),
                onSelected: (String v) => _attachFile(image: v == 'image'),
                itemBuilder: (BuildContext _) => const <PopupMenuEntry<String>>[
                  PopupMenuItem<String>(
                      value: 'image',
                      child:
                          ListTile(dense: true, leading: Icon(Icons.image_outlined), title: Text('Photo'))),
                  PopupMenuItem<String>(
                      value: 'file',
                      child: ListTile(
                          dense: true,
                          leading: Icon(Icons.attach_file_rounded),
                          title: Text('Document, audio or video'))),
                ],
              ),
              Expanded(
                child: CallbackShortcuts(
                  bindings: <ShortcutActivator, VoidCallback>{
                    const SingleActivator(LogicalKeyboardKey.enter): _submit,
                    const SingleActivator(LogicalKeyboardKey.escape): () => setState(() {
                          if (_editing != null) _input.clear();
                          _editing = null;
                          _replyTo = null;
                        }),
                  },
                  child: TextField(
                    controller: _input,
                    focusNode: _focus,
                    minLines: 1,
                    maxLines: 6,
                    maxLength: maxBodyChars,
                    buildCounter: (BuildContext _,
                            {required int currentLength, required bool isFocused, required int? maxLength}) =>
                        null,
                    textInputAction: TextInputAction.newline,
                    onChanged: _onChanged,
                    decoration: InputDecoration(
                      hintText: _editing != null ? 'Edit message' : 'Message',
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(4),
                        borderSide: BorderSide(color: p.border),
                      ),
                      enabledBorder: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(4),
                        borderSide: BorderSide(color: p.border),
                      ),
                      focusedBorder: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(4),
                        borderSide: BorderSide(color: p.accent),
                      ),
                    ),
                  ),
                ),
              ),
              if (_editing == null)
                Padding(
                  padding: const EdgeInsets.only(bottom: 2),
                  child: IconButton(
                    tooltip: _viewOnce
                        ? 'View once: ON — erased on their device after reading'
                        : 'Send the next message as view-once',
                    isSelected: _viewOnce,
                    color: _viewOnce ? p.accent : p.textSecondary,
                    icon: Icon(_viewOnce
                        ? Icons.visibility_off_rounded
                        : Icons.visibility_off_outlined),
                    onPressed: () => setState(() => _viewOnce = !_viewOnce),
                  ),
                ),
              if (_editing == null)
                Padding(
                  padding: const EdgeInsets.only(bottom: 2),
                  child: IconButton(
                    tooltip: 'Record a voice message',
                    onPressed: _sending ? null : () => setState(() => _recording = true),
                    icon: Icon(Icons.mic_none_rounded, color: p.textSecondary),
                  ),
                ),
              const SizedBox(width: 6),
              Padding(
                padding: const EdgeInsets.only(bottom: 2),
                child: IconButton.filled(
                  tooltip: _editing != null ? 'Save edit' : 'Send (Enter)',
                  onPressed: _sending ? null : _submit,
                  icon: _sending
                      ? const SizedBox(
                          width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2))
                      : Icon(_editing != null ? Icons.check_rounded : Icons.send_rounded, size: 20),
                ),
              ),
            ]),
        ]),
      ),
    );
  }
}
