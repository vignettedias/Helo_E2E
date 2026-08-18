/// Account and device setup.
///
/// The security note on this screen is not decoration. Users routinely assume
/// their account password protects their messages; it does not. Stating the
/// separation up front is part of not misrepresenting what the app provides.
library;

import 'dart:math';

import 'package:flutter/material.dart';

import '../../data/relay_client.dart';
import '../../domain/session_manager.dart';
import '../../storage/crypto_storage.dart';
import '../theme.dart';

class OnboardingScreen extends StatefulWidget {
  const OnboardingScreen({
    required this.storage,
    required this.relay,
    required this.onRegistered,
    super.key,
  });

  final CryptoStorage storage;
  final RelayClient relay;
  final void Function(SessionManager) onRegistered;

  @override
  State<OnboardingScreen> createState() => _OnboardingScreenState();
}

class _OnboardingScreenState extends State<OnboardingScreen> {
  final TextEditingController _username = TextEditingController();
  final TextEditingController _password = TextEditingController();
  bool _createAccount = true;
  bool _busy = false;
  String? _error;

  String _generateDeviceId() {
    final Random rng = Random.secure();
    final String suffix = List<int>.generate(6, (_) => rng.nextInt(256))
        .map((int b) => b.toRadixString(16).padLeft(2, '0'))
        .join();
    return 'device-$suffix';
  }

  Future<void> _submit() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final String deviceId = _generateDeviceId();
      final SessionManager manager = SessionManager(
        storage: widget.storage,
        relay: widget.relay,
        deviceId: deviceId,
      );
      await manager.loadOrCreateIdentity();
      await manager.registerWithRelay(
        username: _username.text.trim(),
        password: _password.text,
        createAccount: _createAccount,
      );
      widget.onRegistered(manager);
    } on RelayException catch (e) {
      setState(() => _error = switch (e.code) {
            'username_taken' => 'That username is already registered.',
            'invalid_credentials' => 'Incorrect username or password.',
            'weak_password' => 'Password must be at least 12 characters.',
            'rate_limited' => 'Too many attempts. Wait and try again.',
            _ => 'Could not reach the relay (${e.code}).',
          });
    } catch (_) {
      setState(() => _error = 'Could not reach the relay.');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  void dispose() {
    _username.dispose();
    _password.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: <Widget>[
              const SizedBox(height: 32),
              const Icon(Icons.lock_outline,
                  size: 40, color: HeloColors.accent),
              const SizedBox(height: 14),
              const Text('helo',
                  textAlign: TextAlign.center,
                  style: TextStyle(fontSize: 28, letterSpacing: 3)),
              const SizedBox(height: 6),
              const Text(
                'end-to-end encrypted messaging',
                textAlign: TextAlign.center,
                style: TextStyle(color: HeloColors.textFaint, fontSize: 12),
              ),
              const SizedBox(height: 36),
              TextField(
                controller: _username,
                decoration: const InputDecoration(hintText: 'username'),
                autocorrect: false,
                enableSuggestions: false,
              ),
              const SizedBox(height: 12),
              TextField(
                controller: _password,
                obscureText: true,
                decoration: const InputDecoration(
                    hintText: 'password (12+ characters)'),
              ),
              const SizedBox(height: 12),
              Row(
                children: <Widget>[
                  Checkbox(
                    value: _createAccount,
                    onChanged: (bool? v) =>
                        setState(() => _createAccount = v ?? false),
                  ),
                  const Text('Create a new account',
                      style: TextStyle(fontSize: 13)),
                ],
              ),
              if (_error != null) ...<Widget>[
                const SizedBox(height: 8),
                Text(_error!,
                    style: const TextStyle(
                        color: HeloColors.danger, fontSize: 12)),
              ],
              const SizedBox(height: 20),
              FilledButton(
                onPressed: _busy ? null : _submit,
                child: Text(_busy
                    ? 'generating keys\u2026'
                    : _createAccount
                        ? 'Create account'
                        : 'Sign in'),
              ),
              const SizedBox(height: 32),
              Container(
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  color: HeloColors.surface,
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(color: HeloColors.border),
                ),
                child: const Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: <Widget>[
                    Text('What this password does \u2014 and does not do',
                        style: TextStyle(
                            fontSize: 12, fontWeight: FontWeight.w700)),
                    SizedBox(height: 8),
                    Text(
                      'Your password authenticates you to the relay server. It '
                      'does NOT encrypt your messages and it cannot decrypt '
                      'them. Message encryption uses keys generated on this '
                      'device that never leave it \u2014 not even to the server, '
                      'and not to us.\n\n'
                      'This means: if you lose this device, your message '
                      'history cannot be recovered by resetting your password. '
                      'That is the intended behaviour, not a limitation.',
                      style: TextStyle(
                          color: HeloColors.textSecondary,
                          fontSize: 11.5,
                          height: 1.5),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
