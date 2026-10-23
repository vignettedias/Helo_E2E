/// Welcome, registration and sign-in.
///
/// The note on this screen is not decoration: users routinely assume their
/// account password protects their messages. It does not, and saying so up
/// front is part of not misrepresenting what the app provides.
library;

import 'package:flutter/material.dart';

import '../../data/relay_address.dart';
import '../../data/relay_client.dart';
import '../../domain/messenger.dart';
import '../../storage/crypto_storage.dart';
import 'crypto_lab_screen.dart';
import '../theme.dart';

class OnboardingScreen extends StatefulWidget {
  const OnboardingScreen({
    required this.storage,
    required this.relay,
    required this.onReady,
    required this.onRelayChanged,
    super.key,
  });

  final CryptoStorage storage;
  final RelayClient relay;
  final void Function(Messenger) onReady;

  /// Point this device at a different relay (a packaged app cannot guess the
  /// address of a relay running on someone's laptop).
  final void Function(String) onRelayChanged;

  @override
  State<OnboardingScreen> createState() => _OnboardingScreenState();
}

class _OnboardingScreenState extends State<OnboardingScreen> {
  final GlobalKey<FormState> _form = GlobalKey<FormState>();
  final TextEditingController _username = TextEditingController();
  final TextEditingController _password = TextEditingController();
  final TextEditingController _confirm = TextEditingController();
  bool _signUp = true;
  bool _busy = false;
  bool _obscure = true;
  String? _error;

  static final RegExp _usernameRule = RegExp(r'^[a-z0-9][a-z0-9._-]{2,31}$');

  /// Ask for a relay address. Offered only before this device is registered:
  /// sessions and prekeys live on one relay, so moving an existing device
  /// would strand them.
  Future<void> _changeRelay() async {
    final TextEditingController ctl = TextEditingController(text: widget.relay.baseUrl);
    String? problem;
    final String? chosen = await showDialog<String>(
      context: context,
      builder: (BuildContext ctx) => StatefulBuilder(
        builder: (BuildContext ctx, StateSetter setLocal) => AlertDialog(
          title: const Text('Relay address'),
          content: SizedBox(
            width: 380,
            child: Column(mainAxisSize: MainAxisSize.min, children: <Widget>[
              TextField(
                controller: ctl,
                autofocus: true,
                autocorrect: false,
                keyboardType: TextInputType.url,
                decoration: InputDecoration(
                  hintText: 'http://192.168.1.20:8443',
                  errorText: problem,
                ),
              ),
              const SizedBox(height: 10),
              Text(
                'The address printed by scripts/run_demo.py on the computer running the relay. '
                'Scheme, host and port only.',
                style: TextStyle(color: HeloPalette.of(ctx).textFaint, fontSize: 11.5),
              ),
            ]),
          ),
          actions: <Widget>[
            TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
            FilledButton(
              onPressed: () {
                final String? clean = normaliseRelayUrl(ctl.text);
                if (clean == null) {
                  setLocal(() => problem = 'Needs to look like http://host:port');
                  return;
                }
                Navigator.pop(ctx, clean);
              },
              child: const Text('Use this relay'),
            ),
          ],
        ),
      ),
    );
    ctl.dispose();
    if (chosen != null) widget.onRelayChanged(chosen);
  }

  Future<void> _submit() async {
    if (!(_form.currentState?.validate() ?? false)) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final Messenger m = await Messenger.register(
        storage: widget.storage,
        relay: widget.relay,
        username: _username.text,
        password: _password.text,
        createAccount: _signUp,
      );
      widget.onReady(m);
    } on RelayException catch (e) {
      setState(() => _error = switch (e.code) {
            'username_taken' => 'That username is taken.',
            // Same message for "no such user" and "wrong password": the relay
            // deliberately does not reveal which.
            'invalid_credentials' => 'Incorrect username or password.',
            'weak_password' => 'Password must be at least 12 characters.',
            'invalid_username' || 'validation_failed' =>
              'Usernames are 3–32 characters: letters, digits, ".", "_" or "-".',
            'rate_limited' => 'Too many attempts. Wait a few minutes and try again.',
            _ => 'The relay refused the request (${e.code}).',
          });
    } on Object {
      setState(() => _error = 'Could not reach the relay at ${widget.relay.baseUrl}.');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  void dispose() {
    _username.dispose();
    _password.dispose();
    _confirm.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final HeloPalette p = HeloPalette.of(context);
    return Scaffold(
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 420),
            child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: <Widget>[
              Container(
                width: 76,
                height: 76,
                alignment: Alignment.center,
                margin: const EdgeInsets.only(bottom: 16),
                decoration: BoxDecoration(shape: BoxShape.circle, color: p.accent.withValues(alpha: 0.12)),
                child: Icon(Icons.lock_rounded, size: 36, color: p.accent),
              ),
              const Text('HELO',
                  textAlign: TextAlign.center,
                  style: TextStyle(fontSize: 30, fontWeight: FontWeight.w800, letterSpacing: 4)),
              const SizedBox(height: 6),
              Text('Private messaging, end-to-end encrypted',
                  textAlign: TextAlign.center, style: TextStyle(color: p.textSecondary)),
              const SizedBox(height: 28),
              SegmentedButton<bool>(
                segments: const <ButtonSegment<bool>>[
                  ButtonSegment<bool>(value: true, label: Text('Create account')),
                  ButtonSegment<bool>(value: false, label: Text('Sign in')),
                ],
                selected: <bool>{_signUp},
                onSelectionChanged: (Set<bool> v) => setState(() {
                  _signUp = v.first;
                  _error = null;
                }),
              ),
              const SizedBox(height: 18),
              Form(
                key: _form,
                child: AutofillGroup(
                  child: Column(children: <Widget>[
                    TextFormField(
                      controller: _username,
                      autocorrect: false,
                      enableSuggestions: false,
                      autofillHints: const <String>[AutofillHints.username],
                      decoration: const InputDecoration(
                          labelText: 'Username', prefixIcon: Icon(Icons.alternate_email_rounded)),
                      validator: (String? v) {
                        final String u = (v ?? '').trim().toLowerCase();
                        if (u.isEmpty) return 'Enter a username';
                        if (_signUp && !_usernameRule.hasMatch(u)) {
                          return '3–32 characters: letters, digits, ".", "_" or "-"';
                        }
                        return null;
                      },
                    ),
                    const SizedBox(height: 12),
                    TextFormField(
                      controller: _password,
                      obscureText: _obscure,
                      autofillHints: <String>[_signUp ? AutofillHints.newPassword : AutofillHints.password],
                      decoration: InputDecoration(
                        labelText: 'Password',
                        prefixIcon: const Icon(Icons.password_rounded),
                        suffixIcon: IconButton(
                          icon: Icon(_obscure ? Icons.visibility_outlined : Icons.visibility_off_outlined),
                          onPressed: () => setState(() => _obscure = !_obscure),
                        ),
                      ),
                      validator: (String? v) =>
                          (v ?? '').length < 12 ? 'At least 12 characters' : null,
                      onFieldSubmitted: (_) => _signUp ? null : _submit(),
                    ),
                    if (_signUp) ...<Widget>[
                      const SizedBox(height: 12),
                      TextFormField(
                        controller: _confirm,
                        obscureText: _obscure,
                        decoration: const InputDecoration(
                            labelText: 'Confirm password', prefixIcon: Icon(Icons.password_rounded)),
                        validator: (String? v) =>
                            v != _password.text ? 'Passwords do not match' : null,
                        onFieldSubmitted: (_) => _submit(),
                      ),
                    ],
                  ]),
                ),
              ),
              if (_error != null)
                Padding(
                  padding: const EdgeInsets.only(top: 12),
                  child: Row(children: <Widget>[
                    Icon(Icons.error_outline_rounded, size: 18, color: p.danger),
                    const SizedBox(width: 8),
                    Expanded(child: Text(_error!, style: TextStyle(color: p.danger, fontSize: 13))),
                  ]),
                ),
              const SizedBox(height: 18),
              FilledButton(
                onPressed: _busy ? null : _submit,
                child: _busy
                    ? Row(mainAxisAlignment: MainAxisAlignment.center, children: <Widget>[
                        SizedBox(width: 16, height: 16,
                            child: CircularProgressIndicator(strokeWidth: 2, color: p.onAccent)),
                        const SizedBox(width: 10),
                        const Text('Generating keys on this device…'),
                      ])
                    : Text(_signUp ? 'Create account' : 'Sign in on this device'),
              ),
              const SizedBox(height: 26),
              Container(
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  color: p.surface,
                  borderRadius: BorderRadius.circular(4),
                  border: Border.all(color: p.border),
                ),
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: <Widget>[
                  Row(children: <Widget>[
                    Icon(Icons.info_outline_rounded, size: 16, color: p.accent),
                    const SizedBox(width: 6),
                    const Text('What your password does — and does not do',
                        style: TextStyle(fontWeight: FontWeight.w700, fontSize: 13)),
                  ]),
                  const SizedBox(height: 8),
                  Text(
                    'Your password only signs you in to the relay. It does not encrypt your messages '
                    'and cannot decrypt them: message keys are generated on this device and never '
                    'leave it.\n\n'
                    'So there is no password-based recovery of history. Signing in on a new device '
                    'creates a new, unverified device for your contacts, with no access to old '
                    'messages. That is the intended trade-off of end-to-end encryption.',
                    style: TextStyle(color: p.textSecondary, fontSize: 12.5, height: 1.5),
                  ),
                ]),
              ),
              const SizedBox(height: 6),
              TextButton.icon(
                onPressed: () => Navigator.of(context).push(
                    MaterialPageRoute<void>(builder: (BuildContext _) => const CryptoLabScreen())),
                icon: const Icon(Icons.science_outlined, size: 18),
                label: const Text('Try the crypto lab (no account needed)'),
              ),
              const SizedBox(height: 4),
              TextButton(
                onPressed: _busy ? null : _changeRelay,
                child: Text('Relay: ${widget.relay.baseUrl}  (change)',
                    textAlign: TextAlign.center,
                    style: TextStyle(color: p.textFaint, fontSize: 11)),
              ),
              if (relayTransportIsExposed(widget.relay.baseUrl))
                Padding(
                  padding: const EdgeInsets.only(top: 4),
                  child: Text(
                    'This relay is plain HTTP over a network. Messages stay end-to-end encrypted, '
                    'but anyone on this network can see who you message and when — and can capture '
                    'the sign-in token for this device. Fine for a demo on your own Wi-Fi; not for '
                    'real use.',
                    textAlign: TextAlign.center,
                    style: TextStyle(color: p.warning, fontSize: 11, height: 1.4),
                  ),
                ),
            ]),
          ),
        ),
      ),
    );
  }
}
