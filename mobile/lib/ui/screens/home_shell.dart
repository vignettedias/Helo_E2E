import 'dart:async';

import 'package:flutter/material.dart';

import '../../data/relay_client.dart';
import '../../domain/messenger.dart';
import '../../domain/models.dart';
import '../format.dart';
import '../theme.dart';
import '../widgets/avatar.dart';
import '../widgets/security_badges.dart';
import 'chat_view.dart';
import 'conversation_info.dart';
import 'settings_screen.dart';

const double _wideBreakpoint = 900;
const double _infoBreakpoint = 1300;

class HomeShell extends StatefulWidget {
  const HomeShell({required this.messenger, super.key});
  final Messenger messenger;

  @override
  State<HomeShell> createState() => _HomeShellState();
}

enum _Filter { all, unread, groups }

class _HomeShellState extends State<HomeShell> {
  final TextEditingController _search = TextEditingController();
  StreamSubscription<void>? _changes;
  StreamSubscription<IncomingNotice>? _incoming;
  String? _selected;
  bool _showInfo = false;
  bool _archived = false;
  _Filter _filter = _Filter.all;

  Messenger get _m => widget.messenger;

  @override
  void initState() {
    super.initState();
    _changes = _m.changes.listen((_) {
      if (mounted) setState(() {});
    });
    _incoming = _m.incoming.listen(_notify);
    _m.connection.addListener(_onConnection);
    _m.start();
  }

  void _onConnection() {
    if (mounted) setState(() {});
  }

  /// In-app notification for messages outside the open conversation. (System
  /// notifications are not implemented in this build.)
  void _notify(IncomingNotice n) {
    if (!mounted || !_m.settings.notifications) return;
    if (n.conversation.id == _selected) return;
    final String who = _m.titleOf(n.conversation);
    final String text = !_m.settings.notificationPreviews
        ? 'New message'
        : n.message.attachments.isNotEmpty
            ? '📎 ${n.message.attachments.first.name}'
            : n.message.body;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(
      content: Text('$who: $text', maxLines: 2, overflow: TextOverflow.ellipsis),
      action: SnackBarAction(label: 'Open', onPressed: () => _open(n.conversation.id)),
      duration: const Duration(seconds: 4),
      // A SnackBar with an action persists by default; a message banner must
      // go away on its own.
      persist: false,
    ));
  }

  @override
  void dispose() {
    _changes?.cancel();
    _incoming?.cancel();
    _m.connection.removeListener(_onConnection);
    _search.dispose();
    super.dispose();
  }

  /// Lets the stateless sidebar request a rebuild of the shell.
  void update(VoidCallback change) => setState(change);

  bool _isWide(BuildContext context) => MediaQuery.sizeOf(context).width >= _wideBreakpoint;

  void _open(String convId) {
    if (_isWide(context)) {
      setState(() {
        _selected = convId;
        _showInfo = false;
      });
    } else {
      setState(() => _selected = convId);
      Navigator.of(context).push(MaterialPageRoute<void>(
        builder: (BuildContext ctx) => Scaffold(
          body: ChatView(
            messenger: _m,
            convId: convId,
            onBack: () => Navigator.pop(ctx),
            onOpenInfo: () => Navigator.of(ctx).push(MaterialPageRoute<void>(
              builder: (BuildContext c2) => Scaffold(
                body: ConversationInfo(
                  messenger: _m,
                  convId: convId,
                  onClose: () => Navigator.pop(c2),
                  onDeleted: () => Navigator.of(c2)
                    ..pop()
                    ..pop(),
                ),
              ),
            )),
          ),
        ),
      )).then((_) {
        if (mounted) setState(() => _selected = null);
      });
    }
  }

  void _openSettings() => Navigator.of(context).push(MaterialPageRoute<void>(
      builder: (BuildContext _) => SettingsScreen(messenger: _m)));

  void _toast(String text) =>
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(text)));

  Future<void> _newChat() async {
    final TextEditingController ctl = TextEditingController();
    final String? user = await showDialog<String>(
      context: context,
      builder: (BuildContext ctx) => AlertDialog(
        title: const Text('New chat'),
        content: SizedBox(
          width: 360,
          child: Column(mainAxisSize: MainAxisSize.min, children: <Widget>[
            TextField(
              controller: ctl,
              autofocus: true,
              autocorrect: false,
              decoration: const InputDecoration(
                  hintText: 'username or group invite link', prefixIcon: Icon(Icons.person_search_rounded)),
              onSubmitted: (String v) => Navigator.pop(ctx, v),
            ),
            const SizedBox(height: 10),
            Text(
              'Exact usernames only — there is no searchable directory. They do not need to be '
              'online: their published keys are enough to start an encrypted session. '
              'Paste a group invite link here to ask to join that group.',
              style: TextStyle(color: HeloPalette.of(ctx).textFaint, fontSize: 12),
            ),
          ]),
        ),
        actions: <Widget>[
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(ctx, ctl.text), child: const Text('Start chat')),
        ],
      ),
    );
    ctl.dispose();
    if (user == null || user.trim().isEmpty) return;
    try {
      if (user.trim().startsWith(invitePrefix)) {
        final String admin = await _m.requestJoinByInvite(user);
        _toast('Request sent to ${_m.labelOf(admin)}. The group appears when their app accepts it.');
        return;
      }
      final Conversation c = await _m.openDirect(user.trim().replaceFirst(RegExp('^@'), ''));
      _open(c.id);
    } on MessengerException catch (e) {
      _toast(e.message);
    } on RelayException catch (e) {
      _toast(e.isRateLimited ? 'Too many lookups — wait a moment.' : 'Relay error (${e.code}).');
    } on Object {
      _toast('Could not reach the relay.');
    }
  }

  Future<void> _newGroup() async {
    final TextEditingController name = TextEditingController();
    final TextEditingController members = TextEditingController();
    final bool? ok = await showDialog<bool>(
      context: context,
      builder: (BuildContext ctx) => AlertDialog(
        title: const Text('New group'),
        content: SizedBox(
          width: 380,
          child: Column(mainAxisSize: MainAxisSize.min, children: <Widget>[
            TextField(controller: name, autofocus: true, maxLength: 64,
                decoration: const InputDecoration(hintText: 'Group name', prefixIcon: Icon(Icons.groups_rounded))),
            const SizedBox(height: 8),
            TextField(controller: members,
                decoration: const InputDecoration(hintText: 'Members: usernames, comma separated',
                    prefixIcon: Icon(Icons.person_add_alt_rounded))),
            const SizedBox(height: 10),
            Text('Messages are encrypted separately to each member\'s devices. You will be the admin.',
                style: TextStyle(color: HeloPalette.of(ctx).textFaint, fontSize: 12)),
          ]),
        ),
        actions: <Widget>[
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Create')),
        ],
      ),
    );
    final String groupName = name.text;
    final List<String> users = members.text.split(',');
    name.dispose();
    members.dispose();
    if (!(ok ?? false)) return;
    try {
      final Conversation c = await _m.createGroup(groupName, users);
      _open(c.id);
    } on MessengerException catch (e) {
      _toast(e.message);
    } on RelayException catch (e) {
      _toast(e.statusCode == 404 ? 'One of those users does not exist.' : 'Relay error (${e.code}).');
    }
  }

  @override
  Widget build(BuildContext context) {
    final HeloPalette p = HeloPalette.of(context);
    final double width = MediaQuery.sizeOf(context).width;
    final bool wide = width >= _wideBreakpoint;
    final Widget sidebar = _Sidebar(state: this);
    if (!wide) return Scaffold(body: sidebar, floatingActionButton: _fab());

    final String? sel = _selected != null && _m.conversations.containsKey(_selected) ? _selected : null;
    final bool info = _showInfo && sel != null;
    return Scaffold(
      body: Row(children: <Widget>[
        SizedBox(width: width < 1100 ? 320 : 370, child: sidebar),
        VerticalDivider(width: 1, color: p.border),
        Expanded(
          child: sel == null
              ? const _Welcome()
              : ChatView(
                  key: ValueKey<String>(sel),
                  messenger: _m,
                  convId: sel,
                  onOpenInfo: () => setState(() => _showInfo = !_showInfo),
                ),
        ),
        if (info) ...<Widget>[
          VerticalDivider(width: 1, color: p.border),
          SizedBox(
            width: width >= _infoBreakpoint ? 360 : 320,
            child: ConversationInfo(
              messenger: _m,
              convId: sel,
              onClose: () => setState(() => _showInfo = false),
              onDeleted: () => setState(() {
                _selected = null;
                _showInfo = false;
              }),
            ),
          ),
        ],
      ]),
      floatingActionButton: _fab(),
      floatingActionButtonLocation: FloatingActionButtonLocation.startFloat,
    );
  }

  Widget _fab() => FloatingActionButton.extended(
        heroTag: 'new-chat',
        onPressed: _newChat,
        icon: const Icon(Icons.edit_square),
        label: const Text('New chat'),
      );
}

class _Sidebar extends StatelessWidget {
  const _Sidebar({required this.state});
  final _HomeShellState state;

  Messenger get m => state._m;

  @override
  Widget build(BuildContext context) {
    final HeloPalette p = HeloPalette.of(context);
    final String q = state._search.text.trim().toLowerCase();
    final List<Conversation> all = m.sortedConversations(archived: state._archived);
    final List<Conversation> convs = all.where((Conversation c) {
      if (state._filter == _Filter.unread && c.unread == 0) return false;
      if (state._filter == _Filter.groups && !c.isGroup) return false;
      return q.isEmpty || m.titleOf(c).toLowerCase().contains(q) ||
          (c.peer?.contains(q) ?? false);
    }).toList();
    final List<SearchHit> hits = q.length >= 2 ? m.search(q).take(30).toList() : <SearchHit>[];
    final int archivedCount = m.sortedConversations(archived: true).length;

    return Material(
      color: p.surface,
      child: Column(children: <Widget>[
        SafeArea(
          bottom: false,
          child: Padding(
            padding: const EdgeInsets.fromLTRB(14, 12, 6, 6),
            child: Row(children: <Widget>[
              Icon(Icons.lock_rounded, color: p.accent, size: 22),
              const SizedBox(width: 8),
              const Text('HELO', style: TextStyle(fontSize: 19, fontWeight: FontWeight.w800, letterSpacing: 2)),
              const Spacer(),
              IconButton(tooltip: 'New group', icon: const Icon(Icons.group_add_outlined), onPressed: state._newGroup),
              PopupMenuButton<String>(
                tooltip: 'Menu',
                onSelected: (String v) {
                  if (v == 'settings') state._openSettings();
                  if (v == 'archived') state.update(() => state._archived = !state._archived);
                },
                itemBuilder: (BuildContext _) => <PopupMenuEntry<String>>[
                  const PopupMenuItem<String>(value: 'settings', child: Text('Settings & privacy')),
                  PopupMenuItem<String>(
                      value: 'archived', child: Text(state._archived ? 'Back to chats' : 'Archived chats')),
                ],
                child: Padding(
                  padding: const EdgeInsets.all(6),
                  child: Avatar(label: m.profile.displayName.isEmpty ? m.username : m.profile.displayName,
                      image: m.profile.avatar, size: 32),
                ),
              ),
            ]),
          ),
        ),
        _ConnectionBanner(status: m.connection.value),
        Padding(
          padding: const EdgeInsets.fromLTRB(12, 4, 12, 8),
          child: TextField(
            controller: state._search,
            onChanged: (_) => state.update(() {}),
            decoration: InputDecoration(
              hintText: 'Search chats and messages',
              prefixIcon: const Icon(Icons.search_rounded, size: 20),
              suffixIcon: q.isEmpty
                  ? null
                  : IconButton(
                      icon: const Icon(Icons.close_rounded, size: 18),
                      onPressed: () => state.update(state._search.clear)),
            ),
          ),
        ),
        if (!state._archived)
          SizedBox(
            height: 36,
            child: ListView(scrollDirection: Axis.horizontal, padding: const EdgeInsets.symmetric(horizontal: 12),
                children: <Widget>[
              for (final (_Filter f, String label) in const <(_Filter, String)>[
                (_Filter.all, 'All'), (_Filter.unread, 'Unread'), (_Filter.groups, 'Groups'),
              ])
                Padding(
                  padding: const EdgeInsets.only(right: 6),
                  child: ChoiceChip(
                    label: Text(label),
                    selected: state._filter == f,
                    onSelected: (_) => state.update(() => state._filter = f),
                  ),
                ),
            ]),
          ),
        if (state._archived)
          ListTile(
            dense: true,
            leading: const Icon(Icons.arrow_back_rounded),
            title: const Text('Archived chats'),
            onTap: () => state.update(() => state._archived = false),
          )
        else if (archivedCount > 0)
          ListTile(
            dense: true,
            leading: const Icon(Icons.archive_outlined),
            title: const Text('Archived'),
            trailing: Text('$archivedCount', style: TextStyle(color: p.textFaint)),
            onTap: () => state.update(() => state._archived = true),
          ),
        Expanded(
          child: convs.isEmpty && hits.isEmpty
              ? _EmptyList(searching: q.isNotEmpty, archived: state._archived)
              : ListView(children: <Widget>[
                  for (final Conversation c in convs) _ConversationTile(state: state, c: c),
                  if (hits.isNotEmpty) ...<Widget>[
                    Padding(
                      padding: const EdgeInsets.fromLTRB(16, 14, 16, 4),
                      child: Text('MESSAGES',
                          style: TextStyle(fontSize: 11, letterSpacing: 1.2, color: p.textFaint)),
                    ),
                    for (final SearchHit h in hits)
                      ListTile(
                        dense: true,
                        leading: Avatar(label: m.titleOf(h.conversation), size: 34, group: h.conversation.isGroup),
                        title: Text(m.titleOf(h.conversation), maxLines: 1, overflow: TextOverflow.ellipsis),
                        subtitle: Text(h.message.body, maxLines: 2, overflow: TextOverflow.ellipsis),
                        trailing: Text(listTime(h.message.sentAt),
                            style: TextStyle(color: p.textFaint, fontSize: 11)),
                        onTap: () => state._open(h.conversation.id),
                      ),
                  ],
                  const SizedBox(height: 80),
                ]),
        ),
      ]),
    );
  }
}

class _ConnectionBanner extends StatelessWidget {
  const _ConnectionBanner({required this.status});
  final ConnectionStatus status;

  @override
  Widget build(BuildContext context) {
    final HeloPalette p = HeloPalette.of(context);
    final (Color, IconData, String)? b = switch (status) {
      ConnectionStatus.online => null,
      ConnectionStatus.connecting => (p.info, Icons.sync_rounded, 'Connecting to the relay…'),
      ConnectionStatus.offline => (p.warning, Icons.cloud_off_rounded,
          'Relay unreachable — messages will be sent when it is back'),
      ConnectionStatus.signedOut => (p.danger, Icons.lock_reset_rounded,
          'The relay no longer recognises this device. Reset it in Settings › Account.'),
    };
    if (b == null) return const SizedBox.shrink();
    return Container(
      width: double.infinity,
      margin: const EdgeInsets.fromLTRB(12, 0, 12, 6),
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 7),
      decoration: BoxDecoration(
        color: b.$1.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(10),
      ),
      child: Row(children: <Widget>[
        Icon(b.$2, size: 16, color: b.$1),
        const SizedBox(width: 8),
        Expanded(child: Text(b.$3, style: TextStyle(color: b.$1, fontSize: 12))),
      ]),
    );
  }
}

class _ConversationTile extends StatelessWidget {
  const _ConversationTile({required this.state, required this.c});
  final _HomeShellState state;
  final Conversation c;

  @override
  Widget build(BuildContext context) {
    final HeloPalette p = HeloPalette.of(context);
    final Messenger m = state._m;
    final ChatMessage? last = c.messages.isEmpty ? null : c.messages.last;
    final List<String> typing = m.typingIn(c.id);
    final String preview = typing.isNotEmpty
        ? 'typing…'
        : last == null
            ? 'No messages yet'
            : last.deleted
                ? 'Message deleted'
                : '${last.outgoing && !last.system ? 'You: ' : (c.isGroup && !last.system ? '${m.labelOf(last.author)}: ' : '')}'
                    '${last.attachments.isNotEmpty ? '📎 ' : ''}'
                    '${last.body.isEmpty && last.attachments.isNotEmpty ? last.attachments.first.name : last.body}';
    final bool selected = state._selected == c.id;
    return Material(
      color: selected ? p.accent.withValues(alpha: 0.10) : Colors.transparent,
      child: InkWell(
        onTap: () => state._open(c.id),
        onLongPress: () => _menu(context),
        onSecondaryTap: () => _menu(context),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
          child: Row(children: <Widget>[
            Avatar(
              label: m.titleOf(c),
              group: c.isGroup,
              image: c.isGroup ? c.group!.avatar : m.contacts[c.peer]?.avatar,
              size: 46,
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: <Widget>[
                Row(children: <Widget>[
                  Expanded(
                    child: Text(m.titleOf(c),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: TextStyle(
                            fontWeight: c.unread > 0 ? FontWeight.w700 : FontWeight.w600, fontSize: 15)),
                  ),
                  if (last != null)
                    Text(listTime(last.sentAt),
                        style: TextStyle(
                            color: c.unread > 0 ? p.accent : p.textFaint, fontSize: 11.5)),
                ]),
                const SizedBox(height: 3),
                Row(children: <Widget>[
                  if (last != null && last.outgoing && !last.system && !last.deleted) ...<Widget>[
                    StatusTicks(status: last.status, size: 14),
                    const SizedBox(width: 3),
                  ],
                  Expanded(
                    child: Text(preview,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: TextStyle(
                            color: typing.isNotEmpty ? p.accent : p.textSecondary, fontSize: 13)),
                  ),
                  if (m.hasConflict(c)) Icon(Icons.gpp_bad_outlined, size: 16, color: p.danger),
                  if (c.muted) Icon(Icons.notifications_off_outlined, size: 15, color: p.textFaint),
                  if (c.pinned) Icon(Icons.push_pin_rounded, size: 15, color: p.textFaint),
                  if (c.unread > 0)
                    Container(
                      margin: const EdgeInsets.only(left: 6),
                      padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
                      decoration: BoxDecoration(
                        color: c.muted ? p.textFaint : p.accent,
                        borderRadius: BorderRadius.circular(10),
                      ),
                      child: Text('${c.unread}',
                          style: TextStyle(color: p.onAccent, fontSize: 11, fontWeight: FontWeight.w700)),
                    ),
                ]),
              ]),
            ),
          ]),
        ),
      ),
    );
  }

  Future<void> _menu(BuildContext context) async {
    final Messenger m = state._m;
    final String? v = await showModalBottomSheet<String>(
      context: context,
      builder: (BuildContext ctx) => SafeArea(
        child: Column(mainAxisSize: MainAxisSize.min, children: <Widget>[
          ListTile(leading: Icon(c.pinned ? Icons.push_pin_outlined : Icons.push_pin_rounded),
              title: Text(c.pinned ? 'Unpin' : 'Pin'), onTap: () => Navigator.pop(ctx, 'pin')),
          ListTile(leading: const Icon(Icons.notifications_off_outlined),
              title: Text(c.muted ? 'Unmute' : 'Mute'), onTap: () => Navigator.pop(ctx, 'mute')),
          ListTile(leading: const Icon(Icons.archive_outlined),
              title: Text(c.archived ? 'Unarchive' : 'Archive'), onTap: () => Navigator.pop(ctx, 'archive')),
          ListTile(leading: const Icon(Icons.mark_chat_read_outlined),
              title: const Text('Mark as read'), onTap: () => Navigator.pop(ctx, 'read')),
        ]),
      ),
    );
    switch (v) {
      case 'pin':
        m.setPinned(c.id, !c.pinned);
      case 'mute':
        m.setMuted(c.id, !c.muted);
      case 'archive':
        m.setArchived(c.id, !c.archived);
      case 'read':
        await m.markRead(c.id);
    }
  }
}

class _EmptyList extends StatelessWidget {
  const _EmptyList({required this.searching, required this.archived});
  final bool searching;
  final bool archived;

  @override
  Widget build(BuildContext context) {
    final HeloPalette p = HeloPalette.of(context);
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(28),
        child: Column(mainAxisSize: MainAxisSize.min, children: <Widget>[
          Icon(searching ? Icons.search_off_rounded : Icons.forum_outlined, size: 40, color: p.textFaint),
          const SizedBox(height: 12),
          Text(searching ? 'No matches' : archived ? 'No archived chats' : 'No conversations yet',
              style: TextStyle(color: p.textSecondary, fontWeight: FontWeight.w600)),
          if (!searching && !archived) ...<Widget>[
            const SizedBox(height: 6),
            Text('Start one with New chat — all you need is a username.',
                textAlign: TextAlign.center, style: TextStyle(color: p.textFaint, fontSize: 12.5)),
          ],
        ]),
      ),
    );
  }
}

class _Welcome extends StatelessWidget {
  const _Welcome();

  @override
  Widget build(BuildContext context) {
    final HeloPalette p = HeloPalette.of(context);
    return ColoredBox(
      color: p.background,
      child: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 440),
          child: Column(mainAxisSize: MainAxisSize.min, children: <Widget>[
            Container(
              width: 84,
              height: 84,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: p.accent.withValues(alpha: 0.12),
              ),
              child: Icon(Icons.lock_rounded, size: 40, color: p.accent),
            ),
            const SizedBox(height: 18),
            const Text('HELO', style: TextStyle(fontSize: 24, fontWeight: FontWeight.w800, letterSpacing: 3)),
            const SizedBox(height: 10),
            Text(
              'Pick a conversation, or start a new one. Messages, reactions, receipts and files '
              'are end-to-end encrypted on this device; the relay only ever carries ciphertext.',
              textAlign: TextAlign.center,
              style: TextStyle(color: p.textSecondary, height: 1.5),
            ),
            const SizedBox(height: 12),
            Text('Sessions use the hybrid PQXDH handshake by default (experimental).',
                style: TextStyle(color: p.textFaint, fontSize: 11.5)),
          ]),
        ),
      ),
    );
  }
}
