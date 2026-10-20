import 'dart:typed_data';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

import '../../data/relay_client.dart';
import '../../domain/messenger.dart';
import '../../domain/models.dart';
import '../format.dart';
import '../image_tools.dart';
import '../theme.dart';
import '../widgets/avatar.dart';
import 'security_overview_screen.dart';
import 'verification_dashboard_screen.dart';

/// Every control here has a real effect. Anything not implemented is shown as
/// unavailable instead of as a switch that does nothing.
class SettingsScreen extends StatefulWidget {
  const SettingsScreen({required this.messenger, super.key});
  final Messenger messenger;

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  Messenger get _m => widget.messenger;
  late final TextEditingController _name =
      TextEditingController(text: _m.profile.displayName);
  String? _fingerprint;

  @override
  void initState() {
    super.initState();
    _m.identity.public.fingerprint().then((Uint8List fp) {
      if (!mounted) return;
      final String hex = fp.take(16).map((int b) => b.toRadixString(16).padLeft(2, '0')).join();
      setState(() => _fingerprint =
          List<String>.generate(8, (int i) => hex.substring(i * 4, i * 4 + 4)).join(' '));
    });
  }

  @override
  void dispose() {
    _name.dispose();
    super.dispose();
  }

  void _toast(String t) => ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(t)));

  Future<void> _guard(Future<void> Function() action, {String? done}) async {
    try {
      await action();
      if (done != null) _toast(done);
      if (mounted) setState(() {});
    } on MessengerException catch (e) {
      _toast(e.message);
    } on RelayException catch (e) {
      _toast(switch (e.code) {
        'invalid_credentials' => 'That password is not correct.',
        'weak_password' => 'Use at least 12 characters.',
        'rate_limited' => 'Too many attempts — wait a few minutes.',
        _ => 'Relay error (${e.code}).',
      });
    } on Object {
      _toast('Could not reach the relay.');
    }
  }

  Future<bool> _confirm(String title, String body, String action, {bool danger = false}) async =>
      await showDialog<bool>(
        context: context,
        builder: (BuildContext ctx) => AlertDialog(
          title: Text(title),
          content: Text(body),
          actions: <Widget>[
            TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
            FilledButton(
              style: danger
                  ? FilledButton.styleFrom(
                      backgroundColor: HeloPalette.of(ctx).danger, foregroundColor: Colors.white)
                  : null,
              onPressed: () => Navigator.pop(ctx, true),
              child: Text(action),
            ),
          ],
        ),
      ) ??
      false;

  Future<String?> _password(String title, {bool twoFields = false}) async {
    final TextEditingController a = TextEditingController();
    final TextEditingController b = TextEditingController();
    final String? r = await showDialog<String>(
      context: context,
      builder: (BuildContext ctx) => AlertDialog(
        title: Text(title),
        content: SizedBox(
          width: 360,
          child: Column(mainAxisSize: MainAxisSize.min, children: <Widget>[
            TextField(controller: a, obscureText: true, autofocus: true,
                decoration: InputDecoration(hintText: twoFields ? 'Current password' : 'Password')),
            if (twoFields) ...<Widget>[
              const SizedBox(height: 10),
              TextField(controller: b, obscureText: true,
                  decoration: const InputDecoration(hintText: 'New password (12+ characters)')),
            ],
          ]),
        ),
        actions: <Widget>[
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
          FilledButton(
              onPressed: () => Navigator.pop(ctx, twoFields ? '${a.text}\u0000${b.text}' : a.text),
              child: const Text('Continue')),
        ],
      ),
    );
    a.dispose();
    b.dispose();
    return r;
  }

  Future<void> _pickAvatar() async {
    final FilePickerResult? r = await FilePicker.pickFiles(type: FileType.image, withData: true);
    final Uint8List? bytes = r?.files.single.bytes;
    if (bytes == null) return;
    final Uint8List? small = await shrinkForAvatar(bytes);
    if (small == null) {
      _toast('That image could not be used.');
      return;
    }
    await _guard(() => _m.updateProfile(avatar: small), done: 'Profile picture updated');
  }

  @override
  Widget build(BuildContext context) {
    final HeloPalette p = HeloPalette.of(context);
    final AppSettings s = _m.settings;
    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 720),
          child: ListView(padding: const EdgeInsets.all(16), children: <Widget>[
            // ------------------------------------------------ account
            _Section(title: 'Account', icon: Icons.person_outline_rounded, children: <Widget>[
              Row(children: <Widget>[
                InkWell(
                  borderRadius: BorderRadius.circular(40),
                  onTap: _pickAvatar,
                  child: Avatar(
                      label: _m.profile.displayName.isEmpty ? _m.username : _m.profile.displayName,
                      image: _m.profile.avatar, size: 64),
                ),
                const SizedBox(width: 14),
                Expanded(
                  child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: <Widget>[
                    TextField(
                      controller: _name,
                      maxLength: 64,
                      decoration: const InputDecoration(labelText: 'Display name', counterText: ''),
                      onSubmitted: (String v) => _guard(() => _m.updateProfile(displayName: v),
                          done: 'Name shared with your contacts'),
                    ),
                    const SizedBox(height: 4),
                    Text('@${_m.username} · shared end-to-end, never stored on the relay',
                        style: TextStyle(color: p.textFaint, fontSize: 11.5)),
                  ]),
                ),
                IconButton(
                  tooltip: 'Save name',
                  icon: const Icon(Icons.check_rounded),
                  onPressed: () => _guard(() => _m.updateProfile(displayName: _name.text),
                      done: 'Name shared with your contacts'),
                ),
              ]),
              if (_m.profile.avatar != null)
                Align(
                  alignment: Alignment.centerLeft,
                  child: TextButton(
                    onPressed: () => _guard(() => _m.updateProfile(clearAvatar: true)),
                    child: const Text('Remove picture'),
                  ),
                ),
              _tile(Icons.password_rounded, 'Change password',
                  'Signs out every other session. Never affects your encryption keys.', () async {
                final String? r = await _password('Change password', twoFields: true);
                if (r == null) return;
                final List<String> parts = r.split('\u0000');
                await _guard(() => _m.changePassword(parts[0], parts[1]),
                    done: 'Password changed; other sessions were signed out');
              }),
              _tile(Icons.logout_rounded, 'Log out everywhere',
                  'Revokes every session of this account, then resets this device.', () async {
                if (await _confirm('Log out everywhere?',
                    'All sessions are revoked and this device\'s keys are erased.', 'Log out',
                    danger: true)) {
                  await _guard(_m.logoutEverywhere);
                }
              }),
              _tile(Icons.restart_alt_rounded, 'Reset this device',
                  'Erases identity keys, sessions and history on this device only.', () async {
                if (await _confirm('Reset this device?',
                    'History on this device becomes permanently unreadable. Contacts will see a new, '
                    'unverified device if you sign in again.', 'Reset', danger: true)) {
                  await _guard(_m.resetEverything);
                }
              }, danger: true),
              _tile(Icons.delete_forever_outlined, 'Delete account',
                  'Deletes the account and everything the relay holds for it.', () async {
                final String? pw = await _password('Confirm with your password');
                if (pw == null) return;
                if (await _confirm('Delete account permanently?',
                    'Your username, devices, queued messages and attachments are deleted from the relay.',
                    'Delete', danger: true)) {
                  await _guard(() => _m.deleteAccount(pw));
                }
              }, danger: true),
            ]),

            // ------------------------------------------------ privacy
            _Section(title: 'Privacy', icon: Icons.visibility_off_outlined, children: <Widget>[
              _switch('Show when I\'m online', 'Enforced by the relay. If off, you cannot see others\' status either.',
                  s.showOnline, (bool v) => _guard(() => _m.updateSettings((AppSettings x) => x.showOnline = v))),
              _switch('Show my last seen', 'Enforced by the relay. Reciprocal, like online status.',
                  s.showLastSeen, (bool v) => _guard(() => _m.updateSettings((AppSettings x) => x.showLastSeen = v))),
              _switch('Send read receipts', 'Receipts are end-to-end encrypted messages your device chooses to send.',
                  s.readReceipts, (bool v) => _guard(() => _m.updateSettings((AppSettings x) => x.readReceipts = v))),
              _switch('Send typing indicators', 'Also end-to-end encrypted, and also optional.',
                  s.typingIndicators, (bool v) => _guard(() => _m.updateSettings((AppSettings x) => x.typingIndicators = v))),
              ListTile(
                contentPadding: EdgeInsets.zero,
                leading: const Icon(Icons.timer_outlined),
                title: const Text('Default timer for new chats'),
                trailing: DropdownButton<int>(
                  value: timerChoices.contains(s.defaultDisappearingSeconds) ? s.defaultDisappearingSeconds : 0,
                  underline: const SizedBox.shrink(),
                  onChanged: (int? v) {
                    if (v != null) {
                      _guard(() => _m.updateSettings((AppSettings x) => x.defaultDisappearingSeconds = v));
                    }
                  },
                  items: <DropdownMenuItem<int>>[
                    for (final int v in timerChoices) DropdownMenuItem<int>(value: v, child: Text(timerLabel(v))),
                  ],
                ),
              ),
              _BlockedList(messenger: _m),
              _note(p, 'These settings change what other people are shown. They do not hide network '
                  'timing from the relay, which still sees when your device connects.'),
            ]),

            // ------------------------------------------------ security
            _Section(title: 'Security', icon: Icons.shield_outlined, children: <Widget>[
              _fact(p, 'This device', _m.deviceId),
              _fact(p, 'Identity fingerprint', _fingerprint ?? '…'),
              _fact(p, 'Session setup', 'PQXDH hybrid (X25519 + ML-KEM-768) — experimental'),
              _fact(p, 'Messages', 'Double Ratchet · AES-256-GCM'),
              const SizedBox(height: 6),
              _switch(
                'Allow classical-only contacts',
                'OFF (recommended): sessions require the post-quantum hybrid handshake, and contacts '
                    'whose app offers no post-quantum keys cannot be messaged. ON: such sessions fall '
                    'back to classical X3DH and are labelled "Classical" in the chat.',
                s.allowClassical,
                (bool v) async {
                  if (v &&
                      !await _confirm('Allow classical sessions?',
                          'New sessions with contacts lacking post-quantum keys will use classical X3DH, '
                          'which a future quantum computer could break retroactively. Those chats will '
                          'show a "Classical" warning.', 'Allow')) {
                    return;
                  }
                  await _guard(() => _m.updateSettings((AppSettings x) => x.allowClassical = v));
                },
                danger: true,
              ),
              ListTile(
                contentPadding: EdgeInsets.zero,
                leading: const Icon(Icons.straighten_rounded),
                title: const Text('Message padding'),
                subtitle: Text('Rounds every message up to a size bucket so the relay cannot see its exact length.',
                    style: TextStyle(fontSize: 11.5, color: p.textFaint)),
                trailing: DropdownButton<String>(
                  value: s.padding,
                  underline: const SizedBox.shrink(),
                  onChanged: (String? v) {
                    if (v != null) _guard(() => _m.updateSettings((AppSettings x) => x.padding = v));
                  },
                  items: const <DropdownMenuItem<String>>[
                    DropdownMenuItem<String>(value: 'block-256', child: Text('256-byte blocks')),
                    DropdownMenuItem<String>(value: 'block-160', child: Text('160-byte blocks')),
                    DropdownMenuItem<String>(value: 'pow2-256', child: Text('Powers of two')),
                    DropdownMenuItem<String>(value: 'padme', child: Text('Padmé')),
                    DropdownMenuItem<String>(value: 'none', child: Text('None (exact length)')),
                  ],
                ),
              ),
              _DevicesList(messenger: _m),
              _EventsList(messenger: _m),
            ]),

            // ------------------------------------------------ appearance
            _Section(title: 'Appearance', icon: Icons.palette_outlined, children: <Widget>[
              SegmentedButton<String>(
                segments: const <ButtonSegment<String>>[
                  ButtonSegment<String>(value: 'system', label: Text('System'), icon: Icon(Icons.brightness_auto_outlined)),
                  ButtonSegment<String>(value: 'light', label: Text('Light'), icon: Icon(Icons.light_mode_outlined)),
                  ButtonSegment<String>(value: 'dark', label: Text('Dark'), icon: Icon(Icons.dark_mode_outlined)),
                ],
                selected: <String>{s.theme},
                onSelectionChanged: (Set<String> v) =>
                    _guard(() => _m.updateSettings((AppSettings x) => x.theme = v.first)),
              ),
            ]),

            // ------------------------------------------------ notifications
            _Section(title: 'Notifications', icon: Icons.notifications_outlined, children: <Widget>[
              _switch('In-app message notifications', 'A banner for messages outside the open chat. Muted chats never notify.',
                  s.notifications, (bool v) => _guard(() => _m.updateSettings((AppSettings x) => x.notifications = v))),
              _switch('Show message previews', 'If off, the banner only says "New message".',
                  s.notificationPreviews, (bool v) => _guard(() => _m.updateSettings((AppSettings x) => x.notificationPreviews = v))),
              ListTile(
                contentPadding: EdgeInsets.zero,
                enabled: false,
                leading: const Icon(Icons.notifications_active_outlined),
                title: const Text('System notifications and sounds'),
                subtitle: Text('Unavailable in this build: there is no push service, so notifications '
                    'only appear while the app is open.', style: TextStyle(fontSize: 11.5, color: p.textFaint)),
              ),
            ]),

            // ------------------------------------------------ about
            _Section(title: 'About & verification', icon: Icons.info_outline_rounded, children: <Widget>[
              _tile(Icons.policy_outlined, 'What HELO protects — and what it does not', null, () =>
                  Navigator.of(context).push(MaterialPageRoute<void>(builder: (_) => const SecurityOverviewScreen()))),
              _tile(Icons.fact_check_outlined, 'Verification dashboard',
                  'Results of the project\'s automated security tests, as last run.', () =>
                  Navigator.of(context).push(MaterialPageRoute<void>(
                      builder: (_) => VerificationDashboardScreen(relayBase: _m.relay.baseUrl)))),
              _note(p, 'HELO is a research implementation. It has not been independently audited.'),
            ]),
          ]),
        ),
      ),
    );
  }

  Widget _tile(IconData icon, String title, String? subtitle, VoidCallback onTap, {bool danger = false}) {
    final HeloPalette p = HeloPalette.of(context);
    return ListTile(
      contentPadding: EdgeInsets.zero,
      leading: Icon(icon, color: danger ? p.danger : null),
      title: Text(title, style: TextStyle(color: danger ? p.danger : null)),
      subtitle: subtitle == null ? null : Text(subtitle, style: TextStyle(fontSize: 11.5, color: p.textFaint)),
      onTap: onTap,
    );
  }

  Widget _switch(String title, String subtitle, bool value, ValueChanged<bool> onChanged, {bool danger = false}) {
    final HeloPalette p = HeloPalette.of(context);
    return SwitchListTile(
      contentPadding: EdgeInsets.zero,
      title: Text(title, style: TextStyle(color: danger && value ? p.warning : null)),
      subtitle: Text(subtitle, style: TextStyle(fontSize: 11.5, color: p.textFaint)),
      value: value,
      onChanged: onChanged,
    );
  }

  Widget _fact(HeloPalette p, String label, String value) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 4),
        child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: <Widget>[
          SizedBox(width: 150, child: Text(label, style: TextStyle(color: p.textSecondary, fontSize: 13))),
          Expanded(child: SelectableText(value, style: const TextStyle(fontSize: 13))),
        ]),
      );

  Widget _note(HeloPalette p, String text) => Padding(
        padding: const EdgeInsets.only(top: 6),
        child: Text(text, style: TextStyle(color: p.textFaint, fontSize: 11.5)),
      );
}

class _Section extends StatelessWidget {
  const _Section({required this.title, required this.icon, required this.children});
  final String title;
  final IconData icon;
  final List<Widget> children;

  @override
  Widget build(BuildContext context) {
    final HeloPalette p = HeloPalette.of(context);
    return Padding(
      padding: const EdgeInsets.only(bottom: 14),
      child: Card(
        child: Padding(
          padding: const EdgeInsets.fromLTRB(16, 14, 16, 12),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: <Widget>[
            Row(children: <Widget>[
              Icon(icon, size: 18, color: p.accent),
              const SizedBox(width: 8),
              Text(title, style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 15)),
            ]),
            const SizedBox(height: 10),
            ...children,
          ]),
        ),
      ),
    );
  }
}

class _BlockedList extends StatefulWidget {
  const _BlockedList({required this.messenger});
  final Messenger messenger;
  @override
  State<_BlockedList> createState() => _BlockedListState();
}

class _BlockedListState extends State<_BlockedList> {
  @override
  Widget build(BuildContext context) {
    final List<Contact> blocked =
        widget.messenger.contacts.values.where((Contact c) => c.blocked).toList();
    return ExpansionTile(
      tilePadding: EdgeInsets.zero,
      leading: const Icon(Icons.block_rounded),
      title: Text('Blocked users (${blocked.length})'),
      children: <Widget>[
        if (blocked.isEmpty) const ListTile(dense: true, title: Text('Nobody is blocked.')),
        for (final Contact c in blocked)
          ListTile(
            dense: true,
            title: Text(c.label),
            subtitle: Text('@${c.username}'),
            trailing: TextButton(
              onPressed: () async {
                await widget.messenger.unblock(c.username);
                if (mounted) setState(() {});
              },
              child: const Text('Unblock'),
            ),
          ),
      ],
    );
  }
}

class _DevicesList extends StatefulWidget {
  const _DevicesList({required this.messenger});
  final Messenger messenger;
  @override
  State<_DevicesList> createState() => _DevicesListState();
}

class _DevicesListState extends State<_DevicesList> {
  Future<List<OwnDevice>>? _devices;

  @override
  Widget build(BuildContext context) {
    final HeloPalette p = HeloPalette.of(context);
    return ExpansionTile(
      tilePadding: EdgeInsets.zero,
      leading: const Icon(Icons.devices_rounded),
      title: const Text('Devices & sessions'),
      onExpansionChanged: (bool open) {
        if (open) setState(() => _devices = widget.messenger.devices());
      },
      children: <Widget>[
        FutureBuilder<List<OwnDevice>>(
          future: _devices,
          builder: (BuildContext context, AsyncSnapshot<List<OwnDevice>> snap) {
            if (snap.hasError) return const ListTile(dense: true, title: Text('Could not load devices.'));
            if (!snap.hasData) return const Padding(padding: EdgeInsets.all(12), child: LinearProgressIndicator());
            return Column(children: <Widget>[
              for (final OwnDevice d in snap.data!)
                ListTile(
                  dense: true,
                  leading: Icon(d.current ? Icons.smartphone_rounded : Icons.devices_other_rounded,
                      color: d.revoked ? p.textFaint : null),
                  title: Text('${d.deviceId}${d.current ? ' (this device)' : ''}'),
                  subtitle: Text(d.revoked
                      ? 'Revoked'
                      : 'Added ${listTime(d.registeredAt)}${d.lastSeenAt == null ? '' : ' · active ${listTime(d.lastSeenAt!)}'}'),
                  trailing: d.revoked || d.current
                      ? null
                      : TextButton(
                          onPressed: () async {
                            await widget.messenger.revokeDevice(d.deviceId);
                            setState(() => _devices = widget.messenger.devices());
                          },
                          child: Text('Revoke', style: TextStyle(color: p.danger)),
                        ),
                ),
              Padding(
                padding: const EdgeInsets.all(8),
                child: Text(
                  'Each device has its own keys; nothing private is copied between devices. Messages you '
                  'send from one device are not synced to your others in this version.',
                  style: TextStyle(color: p.textFaint, fontSize: 11.5),
                ),
              ),
            ]);
          },
        ),
      ],
    );
  }
}

class _EventsList extends StatefulWidget {
  const _EventsList({required this.messenger});
  final Messenger messenger;
  @override
  State<_EventsList> createState() => _EventsListState();
}

class _EventsListState extends State<_EventsList> {
  Future<List<SecurityEvent>>? _events;

  static String _label(String kind) => switch (kind) {
        'login' => 'Signed in',
        'login_failed' => 'Failed sign-in attempt',
        'device_registered' => 'Device added',
        'device_revoked' => 'Device revoked',
        'password_changed' => 'Password changed',
        'password_change_failed' => 'Failed password change',
        'sessions_revoked' => 'All sessions signed out',
        _ => kind,
      };

  @override
  Widget build(BuildContext context) {
    final HeloPalette p = HeloPalette.of(context);
    return ExpansionTile(
      tilePadding: EdgeInsets.zero,
      leading: const Icon(Icons.history_rounded),
      title: const Text('Security events'),
      onExpansionChanged: (bool open) {
        if (open) setState(() => _events = widget.messenger.securityEvents());
      },
      children: <Widget>[
        FutureBuilder<List<SecurityEvent>>(
          future: _events,
          builder: (BuildContext context, AsyncSnapshot<List<SecurityEvent>> snap) {
            if (snap.hasError) return const ListTile(dense: true, title: Text('Could not load events.'));
            if (!snap.hasData) return const Padding(padding: EdgeInsets.all(12), child: LinearProgressIndicator());
            if (snap.data!.isEmpty) return const ListTile(dense: true, title: Text('No events.'));
            return Column(children: <Widget>[
              for (final SecurityEvent e in snap.data!.take(30))
                ListTile(
                  dense: true,
                  leading: Icon(
                    e.kind.contains('failed') ? Icons.warning_amber_rounded : Icons.check_circle_outline,
                    color: e.kind.contains('failed') ? p.warning : p.textSecondary,
                    size: 18,
                  ),
                  title: Text(_label(e.kind)),
                  subtitle: Text('${listTime(e.at)} ${clock(e.at)}${e.deviceId == null ? '' : ' · ${e.deviceId}'}'),
                ),
            ]);
          },
        ),
      ],
    );
  }
}

