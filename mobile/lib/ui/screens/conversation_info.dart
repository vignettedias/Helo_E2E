import 'dart:async';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../../crypto/identity.dart' show QrCheck;
import '../../data/relay_client.dart';
import '../../domain/messenger.dart';
import '../../domain/models.dart';
import '../../protocol/payload.dart';
import '../format.dart';
import '../image_tools.dart';
import '../theme.dart';
import '../widgets/avatar.dart';
import '../widgets/message_bubble.dart';
import '../widgets/security_badges.dart';
import 'chat_view.dart' show trustOf;
import 'qr_scan_screen.dart';

class ConversationInfo extends StatefulWidget {
  const ConversationInfo({
    required this.messenger,
    required this.convId,
    required this.onClose,
    this.onDeleted,
    super.key,
  });

  final Messenger messenger;
  final String convId;
  final VoidCallback onClose;
  final VoidCallback? onDeleted;

  @override
  State<ConversationInfo> createState() => _ConversationInfoState();
}

class _ConversationInfoState extends State<ConversationInfo> {
  Messenger get _m => widget.messenger;
  Conversation? get _c => _m.conversations[widget.convId];
  List<DeviceSafety>? _safety;
  StreamSubscription<void>? _sub;

  @override
  void initState() {
    super.initState();
    _sub = _m.changes.listen((_) {
      if (mounted) setState(() {});
    });
    _loadSafety();
  }

  @override
  void didUpdateWidget(ConversationInfo old) {
    super.didUpdateWidget(old);
    if (old.convId != widget.convId) {
      _safety = null;
      _loadSafety();
    }
  }

  @override
  void dispose() {
    _sub?.cancel();
    super.dispose();
  }

  Future<void> _loadSafety() async {
    final Conversation? c = _c;
    if (c == null) return;
    final List<DeviceSafety> all = <DeviceSafety>[];
    for (final String u in c.recipients(_m.username)) {
      all.addAll(await _m.safetyNumbersFor(u));
    }
    if (mounted) setState(() => _safety = all);
  }

  void _toast(String text) =>
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(text)));

  Future<void> _guard(Future<void> Function() action, {String? done}) async {
    try {
      await action();
      if (done != null) _toast(done);
    } on MessengerException catch (e) {
      _toast(e.message);
    } on RelayException catch (e) {
      _toast(e.describe);
    }
  }

  Future<String?> _ask(String title, {String hint = '', String initial = ''}) {
    final TextEditingController ctl = TextEditingController(text: initial);
    return showDialog<String>(
      context: context,
      builder: (BuildContext ctx) => AlertDialog(
        title: Text(title),
        content: TextField(
          controller: ctl,
          autofocus: true,
          decoration: InputDecoration(hintText: hint),
          onSubmitted: (String v) => Navigator.pop(ctx, v),
        ),
        actions: <Widget>[
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(ctx, ctl.text), child: const Text('OK')),
        ],
      ),
    ).whenComplete(ctl.dispose);
  }

  Future<bool> _confirm(String title, String body, String action) async =>
      await showDialog<bool>(
        context: context,
        builder: (BuildContext ctx) => AlertDialog(
          title: Text(title),
          content: Text(body),
          actions: <Widget>[
            TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
            FilledButton(onPressed: () => Navigator.pop(ctx, true), child: Text(action)),
          ],
        ),
      ) ??
      false;

  @override
  Widget build(BuildContext context) {
    final HeloPalette p = HeloPalette.of(context);
    final Conversation? c = _c;
    if (c == null) return const SizedBox.shrink();
    final Contact? contact = c.isGroup ? null : _m.contacts[c.peer];

    return Material(
      color: p.surface,
      child: Column(children: <Widget>[
        Container(
          padding: const EdgeInsets.fromLTRB(8, 8, 8, 8),
          decoration: BoxDecoration(border: Border(bottom: BorderSide(color: p.border))),
          child: SafeArea(
            bottom: false,
            child: Row(children: <Widget>[
              IconButton(icon: const Icon(Icons.close_rounded), onPressed: widget.onClose),
              Text(c.isGroup ? 'Group info' : 'Contact info',
                  style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 16)),
            ]),
          ),
        ),
        Expanded(
          child: ListView(padding: const EdgeInsets.all(16), children: <Widget>[
            Center(
              child: Avatar(
                label: _m.titleOf(c),
                group: c.isGroup,
                image: c.isGroup ? c.group!.avatar : contact?.avatar,
                size: 88,
              ),
            ),
            const SizedBox(height: 12),
            Center(
              child: Text(_m.titleOf(c),
                  style: const TextStyle(fontSize: 20, fontWeight: FontWeight.w700)),
            ),
            Center(
              child: Text(
                c.isGroup ? '${c.group!.members.length} members' : '@${c.peer}',
                style: TextStyle(color: p.textSecondary),
              ),
            ),
            if (c.isGroup && c.group!.admins.contains(_m.username) && !c.group!.removed)
              Center(
                child: Wrap(spacing: 8, children: <Widget>[
                  TextButton.icon(
                    icon: const Icon(Icons.edit_outlined, size: 16),
                    label: const Text('Rename'),
                    onPressed: () async {
                      final String? name = await _ask('Group name', initial: c.group!.name);
                      if (name != null) await _guard(() => _m.renameGroup(c.id, name));
                    },
                  ),
                  TextButton.icon(
                    icon: const Icon(Icons.image_outlined, size: 16),
                    label: const Text('Picture'),
                    onPressed: () => _pickGroupPicture(c),
                  ),
                ]),
              ),
            const SizedBox(height: 18),
            _encryptionCard(c, p),
            const SizedBox(height: 14),
            _verificationCard(c, p),
            const SizedBox(height: 14),
            _settingsCard(c, p),
            const SizedBox(height: 14),
            if (c.isGroup) ...<Widget>[_membersCard(c, p), const SizedBox(height: 14)],
            _mediaCard(c, p),
            const SizedBox(height: 14),
            _dangerCard(c, p, contact),
          ]),
        ),
      ]),
    );
  }

  Widget _card(HeloPalette p, String title, List<Widget> children, {IconData? icon}) => Card(
        child: Padding(
          padding: const EdgeInsets.fromLTRB(14, 12, 14, 10),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: <Widget>[
            Row(children: <Widget>[
              if (icon != null) ...<Widget>[Icon(icon, size: 16, color: p.accent), const SizedBox(width: 6)],
              Text(title.toUpperCase(),
                  style: TextStyle(
                      fontSize: 11, letterSpacing: 1.1, color: p.textFaint, fontWeight: FontWeight.w700)),
            ]),
            const SizedBox(height: 8),
            ...children,
          ]),
        ),
      );

  Widget _fact(HeloPalette p, String label, String value) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 3),
        child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: <Widget>[
          SizedBox(
              width: 120,
              child: Text(label, style: TextStyle(color: p.textSecondary, fontSize: 12.5))),
          Expanded(child: Text(value, style: const TextStyle(fontSize: 12.5))),
        ]),
      );

  /// Only facts the implementation can back: the handshake actually used for
  /// the current session(s), the ratchet, the AEAD and the padding policy.
  Widget _encryptionCard(Conversation c, HeloPalette p) {
    final Set<String> kex = _m.keyEstablishmentOf(c);
    final String handshake = kex.isEmpty
        ? 'No session yet — established with the first message'
        : kex.contains('x3dh')
            ? 'Classical X3DH (X25519) — NOT post-quantum'
            : 'PQXDH hybrid: X25519 + ML-KEM-768 (FIPS 203)';
    return _card(p, 'Encryption', icon: Icons.lock_outline_rounded, <Widget>[
      _fact(p, 'Session setup', handshake),
      _fact(p, 'Messages', 'Double Ratchet (X25519, HKDF-SHA-256), AES-256-GCM'),
      _fact(p, 'Length hiding', 'Padded to ${_m.settings.padding} buckets'),
      _fact(p, 'Relay sees', 'Ciphertext, routing, timing and padded sizes — never content'),
      const SizedBox(height: 6),
      Text(
        'The hybrid handshake is experimental and protects session setup only; later ratchet '
        'steps use classical X25519. It has not been independently audited.',
        style: TextStyle(color: p.textFaint, fontSize: 11.5),
      ),
    ]);
  }

  Widget _verificationCard(Conversation c, HeloPalette p) {
    final List<DeviceSafety>? safety = _safety;
    return _card(p, 'Verification', icon: Icons.verified_user_outlined, <Widget>[
      Row(children: <Widget>[TrustBadge(state: trustOf(_m, c))]),
      const SizedBox(height: 8),
      Text(
        'Encryption proves only that you share keys with SOMEONE. Compare safety numbers in person '
        'or on a call you trust to know it is the right person.',
        style: TextStyle(color: p.textSecondary, fontSize: 12),
      ),
      const SizedBox(height: 6),
      if (safety == null)
        const Padding(
          padding: EdgeInsets.all(8),
          child: Center(child: SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2))),
        )
      else if (safety.isEmpty)
        Text('No devices known yet.', style: TextStyle(color: p.textFaint, fontSize: 12))
      else
        for (final DeviceSafety s in safety)
          ListTile(
            contentPadding: EdgeInsets.zero,
            dense: true,
            leading: Icon(
              s.pin.conflict
                  ? Icons.gpp_bad_outlined
                  : s.pin.verified
                      ? Icons.verified_user_rounded
                      : Icons.devices_rounded,
              color: s.pin.conflict ? p.danger : (s.pin.verified ? p.success : p.textSecondary),
            ),
            title: Text('${_m.labelOf(s.pin.username)} · ${s.pin.deviceId}',
                style: const TextStyle(fontSize: 13)),
            subtitle: Text(
                s.pin.conflict ? 'Key changed — not trusted' : (s.pin.verified ? 'Verified' : 'Not verified'),
                style: TextStyle(fontSize: 11.5, color: s.pin.conflict ? p.danger : p.textFaint)),
            trailing: TextButton(onPressed: () => _showSafety(s), child: const Text('Compare')),
          ),
    ]);
  }

  /// Scan [user]'s displayed code and report the verdict. Only a full match
  /// verifies, and only the device the code belongs to.
  Future<void> _scan(String user) async {
    final String? text = await Navigator.of(context).push<String>(MaterialPageRoute<String>(
        builder: (_) => QrScanScreen(contactLabel: _m.labelOf(user))));
    if (text == null || !mounted) return;
    QrScanOutcome? r;
    await _guard(() async => r = await _m.verifyByScannedCode(user, text));
    final QrScanOutcome? outcome = r;
    if (outcome == null || !mounted) return;
    final String who = _m.labelOf(user);
    final (String title, String body, bool good) = switch (outcome.check) {
      QrCheck.match => ('Verified', 'This device of $who (${outcome.device!.deviceId}) is now verified. '
          'Both of you hold the right keys for each other.', true),
      QrCheck.ownKeyMismatch => ('Do not trust this chat yet',
          "$who's app holds a DIFFERENT key for you than your real one. Someone may be "
          'intercepting this conversation. Nothing was marked verified.', false),
      QrCheck.peerKeyMismatch => ('Code does not match',
          "This code belongs to a key you do not hold for $who. It may be someone else's code, "
          "or $who's key here may have been substituted. Nothing was marked verified.", false),
      QrCheck.notHelo => ('Not a verification code', 'That is not a HELO verification code.', false),
    };
    await _loadSafety();
    if (!mounted) return;
    final HeloPalette p = HeloPalette.of(context);
    await showDialog<void>(
      context: context,
      builder: (BuildContext ctx) => AlertDialog(
        icon: Icon(good ? Icons.verified_user_rounded : Icons.gpp_bad_outlined,
            color: good ? p.success : p.danger, size: 36),
        title: Text(title),
        content: Text(body),
        actions: <Widget>[TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('OK'))],
      ),
    );
  }

  Future<void> _showSafety(DeviceSafety s) async {
    final HeloPalette p = HeloPalette.of(context);
    final List<String> groups = s.safetyNumber.split(' ');
    await showDialog<void>(
      context: context,
      builder: (BuildContext ctx) => StatefulBuilder(
        builder: (BuildContext ctx, StateSetter setLocal) => AlertDialog(
          title: Text('Safety number with ${_m.labelOf(s.pin.username)}'),
          content: SizedBox(
            width: 380,
            child: SingleChildScrollView(
              child: Column(mainAxisSize: MainAxisSize.min, children: <Widget>[
                Container(
                  padding: const EdgeInsets.all(10),
                  color: Colors.white,
                  child: QrImageView(data: s.qrPayload, size: 180, backgroundColor: Colors.white),
                ),
                const SizedBox(height: 14),
                Wrap(
                  alignment: WrapAlignment.center,
                  spacing: 14,
                  runSpacing: 6,
                  children: <Widget>[
                    for (final String g in groups)
                      Text(g,
                          style: const TextStyle(
                              fontFeatures: <FontFeature>[FontFeature.tabularFigures()],
                              fontSize: 17,
                              letterSpacing: 1.5,
                              fontWeight: FontWeight.w600)),
                  ],
                ),
                const SizedBox(height: 14),
                Text(
                  'Both of you should see these exact digits. Compare them in person or on a call — '
                  'never over this app, because whoever could swap keys could swap this number too. '
                  'Or, in person, scan their code: it checks both directions at once.',
                  style: TextStyle(color: p.textSecondary, fontSize: 12),
                ),
                const SizedBox(height: 8),
                SwitchListTile(
                  contentPadding: EdgeInsets.zero,
                  title: const Text('Mark this device as verified'),
                  value: s.pin.verified,
                  onChanged: s.pin.conflict
                      ? null
                      : (bool v) async {
                          await _guard(() => _m.setDeviceVerified(s.pin.deviceId, v));
                          setLocal(() {});
                          if (mounted) setState(() {});
                        },
                ),
              ]),
            ),
          ),
          actions: <Widget>[
            if (!s.pin.conflict)
              TextButton.icon(
                onPressed: () async {
                  Navigator.pop(ctx);
                  await _scan(s.pin.username);
                },
                icon: const Icon(Icons.qr_code_scanner_rounded, size: 18),
                label: const Text('Scan their code'),
              ),
            TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Done')),
          ],
        ),
      ),
    );
  }

  Widget _settingsCard(Conversation c, HeloPalette p) {
    final bool active = !(c.isGroup && c.group!.removed);
    return _card(p, 'Conversation', icon: Icons.tune_rounded, <Widget>[
      ListTile(
        contentPadding: EdgeInsets.zero,
        dense: true,
        leading: const Icon(Icons.timer_outlined),
        title: const Text('Disappearing messages'),
        subtitle: Text(
          'Removes messages from devices after the timer. Cannot stop screenshots or copies.',
          style: TextStyle(fontSize: 11, color: p.textFaint),
        ),
        trailing: DropdownButton<int>(
          value: timerChoices.contains(c.disappearingSeconds) ? c.disappearingSeconds : 0,
          underline: const SizedBox.shrink(),
          onChanged: !active
              ? null
              : (int? v) {
                  if (v != null) _guard(() => _m.setDisappearing(c.id, v));
                },
          items: <DropdownMenuItem<int>>[
            for (final int s in timerChoices)
              DropdownMenuItem<int>(value: s, child: Text(timerLabel(s))),
          ],
        ),
      ),
      SwitchListTile(
        contentPadding: EdgeInsets.zero,
        dense: true,
        secondary: const Icon(Icons.notifications_off_outlined),
        title: const Text('Mute notifications'),
        value: c.muted,
        onChanged: (bool v) => _m.setMuted(c.id, v),
      ),
      SwitchListTile(
        contentPadding: EdgeInsets.zero,
        dense: true,
        secondary: const Icon(Icons.push_pin_outlined),
        title: const Text('Pin to top'),
        value: c.pinned,
        onChanged: (bool v) => _m.setPinned(c.id, v),
      ),
      SwitchListTile(
        contentPadding: EdgeInsets.zero,
        dense: true,
        secondary: const Icon(Icons.archive_outlined),
        title: const Text('Archived'),
        value: c.archived,
        onChanged: (bool v) => _m.setArchived(c.id, v),
      ),
    ]);
  }

  Future<void> _showInvite(Conversation c) async {
    final String link = _m.createInviteLink(c.id);
    final HeloPalette p = HeloPalette.of(context);
    await showDialog<void>(
      context: context,
      builder: (BuildContext ctx) => AlertDialog(
        title: const Text('Invite link'),
        content: SizedBox(
          width: 380,
          child: SingleChildScrollView(
            child: Column(mainAxisSize: MainAxisSize.min, children: <Widget>[
              Container(
                padding: const EdgeInsets.all(10),
                color: Colors.white,
                child: QrImageView(data: link, size: 180, backgroundColor: Colors.white),
              ),
              const SizedBox(height: 10),
              SelectableText(link, style: const TextStyle(fontSize: 11.5)),
              const SizedBox(height: 10),
              Text(
                'Anyone with this link can join. It works for 7 days or 50 joins, and only while '
                'your app is online to accept requests (your device checks the link; the relay '
                'never sees it). Share it privately.',
                style: TextStyle(color: p.textSecondary, fontSize: 12),
              ),
            ]),
          ),
        ),
        actions: <Widget>[
          TextButton(
            onPressed: () {
              _m.revokeInviteLinks(c.id);
              Navigator.pop(ctx);
              _toast('All invite links for this group were revoked');
            },
            child: Text('Revoke all', style: TextStyle(color: p.danger)),
          ),
          TextButton(
            onPressed: () async {
              await Clipboard.setData(ClipboardData(text: link));
              if (ctx.mounted) Navigator.pop(ctx);
              _toast('Invite link copied');
            },
            child: const Text('Copy'),
          ),
        ],
      ),
    );
    if (mounted) setState(() {});
  }

  Widget _membersCard(Conversation c, HeloPalette p) {
    final GroupState g = c.group!;
    final bool admin = g.admins.contains(_m.username) && !g.removed;
    return _card(p, 'Members', icon: Icons.groups_outlined, <Widget>[
      if (admin)
        ListTile(
          contentPadding: EdgeInsets.zero,
          dense: true,
          leading: Icon(Icons.person_add_alt_rounded, color: p.accent),
          title: Text('Add members', style: TextStyle(color: p.accent)),
          onTap: () async {
            final String? names = await _ask('Add members', hint: 'usernames, comma separated');
            if (names == null || names.trim().isEmpty) return;
            await _guard(() => _m.addMembers(c.id, names.split(',')), done: 'Members added');
          },
        ),
      if (admin)
        ListTile(
          contentPadding: EdgeInsets.zero,
          dense: true,
          leading: Icon(Icons.link_rounded, color: p.accent),
          title: Text('Invite link', style: TextStyle(color: p.accent)),
          subtitle: Text(
              g.invites.isEmpty ? 'Let people join by link' : '${g.invites.length} active link(s)',
              style: TextStyle(fontSize: 11.5, color: p.textFaint)),
          onTap: () => _showInvite(c),
        ),
      for (final String u in g.members)
        ListTile(
          contentPadding: EdgeInsets.zero,
          dense: true,
          leading: Avatar(label: _m.labelOf(u), image: _m.contacts[u]?.avatar, size: 32),
          title: Text(u == _m.username ? 'You' : _m.labelOf(u)),
          subtitle: Text('@$u', style: TextStyle(fontSize: 11, color: p.textFaint)),
          trailing: Row(mainAxisSize: MainAxisSize.min, children: <Widget>[
            if (g.admins.contains(u))
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                decoration: BoxDecoration(
                  color: p.accent.withValues(alpha: 0.15),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Text('Admin', style: TextStyle(color: p.accent, fontSize: 11)),
              ),
            if (admin && u != _m.username)
              PopupMenuButton<String>(
                onSelected: (String action) async {
                  switch (action) {
                    case 'admin':
                      await _guard(() => _m.setAdmin(c.id, u, true));
                    case 'unadmin':
                      await _guard(() => _m.setAdmin(c.id, u, false));
                    case 'remove':
                      if (await _confirm('Remove ${_m.labelOf(u)}?',
                          'They will no longer receive messages sent to this group.', 'Remove')) {
                        await _guard(() => _m.removeMember(c.id, u));
                      }
                  }
                },
                itemBuilder: (BuildContext _) => <PopupMenuEntry<String>>[
                  if (!g.admins.contains(u))
                    const PopupMenuItem<String>(value: 'admin', child: Text('Make admin')),
                  if (g.admins.contains(u))
                    const PopupMenuItem<String>(value: 'unadmin', child: Text('Dismiss as admin')),
                  const PopupMenuItem<String>(value: 'remove', child: Text('Remove from group')),
                ],
              ),
          ]),
        ),
      const SizedBox(height: 4),
      Text(
        'Groups use pairwise encryption to each member. Removed members get nothing sent '
        'afterwards; new members get nothing sent before they joined.',
        style: TextStyle(color: p.textFaint, fontSize: 11.5),
      ),
    ]);
  }

  Future<void> _pickGroupPicture(Conversation c) async {
    final FilePickerResult? r = await FilePicker.pickFiles(type: FileType.image, withData: true);
    final Uint8List? bytes = r?.files.single.bytes;
    if (bytes == null) return;
    final Uint8List? small = await shrinkForAvatar(bytes);
    if (small == null) {
      _toast('That image could not be used.');
      return;
    }
    await _guard(() => _m.setGroupAvatar(c.id, small));
  }

  Widget _mediaCard(Conversation c, HeloPalette p) {
    final List<AttachmentRef> images = <AttachmentRef>[];
    final List<AttachmentRef> docs = <AttachmentRef>[];
    for (final ChatMessage m in c.messages.reversed) {
      for (final AttachmentRef a in m.attachments) {
        (a.isImage ? images : docs).add(a);
      }
    }
    return _card(p, 'Shared media & documents', icon: Icons.perm_media_outlined, <Widget>[
      if (images.isEmpty && docs.isEmpty)
        Text('Nothing shared yet.', style: TextStyle(color: p.textFaint, fontSize: 12)),
      if (images.isNotEmpty)
        Wrap(spacing: 6, runSpacing: 6, children: <Widget>[
          for (final AttachmentRef a in images.take(9))
            SizedBox(width: 90, height: 90, child: ClipRRect(
              borderRadius: BorderRadius.circular(8),
              child: FittedBox(fit: BoxFit.cover, child: AttachmentView(messenger: _m, ref: a)),
            )),
        ]),
      for (final AttachmentRef a in docs.take(10))
        Padding(padding: const EdgeInsets.only(top: 6), child: AttachmentView(messenger: _m, ref: a)),
    ]);
  }

  Widget _dangerCard(Conversation c, HeloPalette p, Contact? contact) {
    return _card(p, c.isGroup ? 'Group' : 'Contact', <Widget>[
      if (!c.isGroup) ...<Widget>[
        ListTile(
          contentPadding: EdgeInsets.zero,
          dense: true,
          leading: Icon(Icons.block_rounded, color: p.danger),
          title: Text((contact?.blocked ?? false) ? 'Unblock ${_m.titleOf(c)}' : 'Block ${_m.titleOf(c)}',
              style: TextStyle(color: p.danger)),
          subtitle: Text('Enforced by the relay: their messages are dropped and your devices are '
              'hidden from them. They are not told.', style: TextStyle(fontSize: 11, color: p.textFaint)),
          onTap: () async {
            if (contact?.blocked ?? false) {
              await _guard(() => _m.unblock(c.peer!), done: 'Unblocked');
            } else if (await _confirm('Block ${_m.titleOf(c)}?',
                'You will not receive their messages until you unblock them.', 'Block')) {
              await _guard(() => _m.block(c.peer!), done: 'Blocked');
            }
          },
        ),
        ListTile(
          contentPadding: EdgeInsets.zero,
          dense: true,
          leading: Icon(Icons.flag_outlined, color: p.warning),
          title: const Text('Report'),
          subtitle: Text('Sends the relay operator their username and your reason — no messages.',
              style: TextStyle(fontSize: 11, color: p.textFaint)),
          onTap: () => _report(c.peer!),
        ),
      ],
      if (c.isGroup && !c.group!.removed)
        ListTile(
          contentPadding: EdgeInsets.zero,
          dense: true,
          leading: Icon(Icons.logout_rounded, color: p.danger),
          title: Text('Leave group', style: TextStyle(color: p.danger)),
          onTap: () async {
            if (await _confirm('Leave "${c.group!.name}"?',
                'You will stop receiving this group\'s messages.', 'Leave')) {
              await _guard(() => _m.leaveGroup(c.id));
            }
          },
        ),
      ListTile(
        contentPadding: EdgeInsets.zero,
        dense: true,
        leading: Icon(Icons.delete_outline_rounded, color: p.danger),
        title: Text('Delete conversation from this device', style: TextStyle(color: p.danger)),
        onTap: () async {
          if (await _confirm('Delete conversation?',
              'Removes its history from this device only.', 'Delete')) {
            await _m.deleteConversation(c.id);
            widget.onDeleted?.call();
          }
        },
      ),
    ]);
  }

  Future<void> _report(String user) async {
    String reason = 'spam';
    final TextEditingController note = TextEditingController();
    final bool? ok = await showDialog<bool>(
      context: context,
      builder: (BuildContext ctx) => StatefulBuilder(
        builder: (BuildContext ctx, StateSetter setLocal) => AlertDialog(
          title: Text('Report @$user'),
          content: Column(mainAxisSize: MainAxisSize.min, children: <Widget>[
            RadioGroup<String>(
              groupValue: reason,
              onChanged: (String? x) => setLocal(() => reason = x ?? reason),
              child: Column(mainAxisSize: MainAxisSize.min, children: <Widget>[
                for (final (String v, String label) in const <(String, String)>[
                  ('spam', 'Spam'),
                  ('abuse', 'Harassment or abuse'),
                  ('impersonation', 'Impersonation'),
                  ('other', 'Something else'),
                ])
                  RadioListTile<String>(value: v, dense: true, title: Text(label)),
              ]),
            ),
            TextField(controller: note, maxLength: 500,
                decoration: const InputDecoration(hintText: 'Optional note (not your messages)')),
          ]),
          actions: <Widget>[
            TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
            FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Report')),
          ],
        ),
      ),
    );
    if (ok ?? false) {
      await _guard(() => _m.report(user, reason, note: note.text), done: 'Report sent');
    }
    note.dispose();
  }
}
