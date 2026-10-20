/// Application root: dependency wiring, theming and top-level routing.
library;

import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

import 'data/relay_client.dart';
import 'domain/messenger.dart';
import 'storage/crypto_storage.dart';
import 'ui/screens/home_shell.dart';
import 'ui/screens/onboarding_screen.dart';
import 'ui/theme.dart';

const String _relayOverride = String.fromEnvironment('HELO_RELAY_URL');

/// Relay endpoint. Override at build time:
///   flutter run --dart-define=HELO_RELAY_URL=https://relay.example.com
///
/// Defaults: a browser build served over plain HTTP talks to port 8443 on the
/// host that served the page (one served over HTTPS assumes the TLS proxy on
/// the same host); the Android emulator reaches the host machine at 10.0.2.2;
/// everything else uses localhost.
String get relayUrl {
  if (_relayOverride.isNotEmpty) return _relayOverride;
  if (kIsWeb) {
    final Uri page = Uri.base;
    return page.scheme == 'https' ? 'https://${page.host}' : 'http://${page.host}:8443';
  }
  if (defaultTargetPlatform == TargetPlatform.android) return 'http://10.0.2.2:8443';
  return 'http://localhost:8443';
}

class HeloApp extends StatefulWidget {
  const HeloApp({super.key});

  @override
  State<HeloApp> createState() => _HeloAppState();
}

class _HeloAppState extends State<HeloApp> {
  final CryptoStorage _storage = PlatformCryptoStorage();
  final GlobalKey<NavigatorState> _navigator = GlobalKey<NavigatorState>();
  late final RelayClient _relay = RelayClient(baseUrl: relayUrl);
  Messenger? _messenger;
  StreamSubscription<void>? _sub;
  bool _ready = false;
  String? _bootError;

  @override
  void initState() {
    super.initState();
    _bootstrap();
  }

  Future<void> _bootstrap() async {
    try {
      final Messenger? m = await Messenger.restore(storage: _storage, relay: _relay);
      if (m != null) _adopt(m);
    } on Object {
      // Stored key material that cannot be read is not repaired or guessed
      // at. The user is told, and can reset the device to start cleanly.
      _bootError = 'Stored key material could not be read.';
    }
    if (mounted) setState(() => _ready = true);
  }

  void _adopt(Messenger m) {
    _sub?.cancel();
    // Rebuild on settings changes so the theme follows the user's choice.
    _sub = m.changes.listen((_) {
      if (mounted) setState(() {});
    });
    m.onReset = () {
      _sub?.cancel();
      // Reset can be triggered from a pushed screen (Settings): close every
      // route so onboarding is what the user sees, not a stale settings page.
      _navigator.currentState?.popUntil((Route<dynamic> r) => r.isFirst);
      if (mounted) setState(() => _messenger = null);
    };
    _messenger = m;
  }

  Future<void> _wipeAfterBootError() async {
    await _storage.wipeAll();
    setState(() => _bootError = null);
  }

  @override
  void dispose() {
    _sub?.cancel();
    unawaited(_messenger?.dispose());
    _relay.close();
    super.dispose();
  }

  ThemeMode get _themeMode => switch (_messenger?.settings.theme) {
        'light' => ThemeMode.light,
        'dark' => ThemeMode.dark,
        _ => ThemeMode.system,
      };

  @override
  Widget build(BuildContext context) {
    final Messenger? m = _messenger;
    return MaterialApp(
      navigatorKey: _navigator,
      title: 'HELO',
      debugShowCheckedModeBanner: false,
      theme: buildTheme(Brightness.light),
      darkTheme: buildTheme(Brightness.dark),
      themeMode: _themeMode,
      home: !_ready
          ? const _Splash()
          : _bootError != null
              ? _BootError(message: _bootError!, onReset: _wipeAfterBootError)
              : m == null
                  ? OnboardingScreen(
                      storage: _storage,
                      relay: _relay,
                      onReady: (Messenger fresh) => setState(() => _adopt(fresh)),
                    )
                  : HomeShell(key: ValueKey<String>(m.deviceId), messenger: m),
    );
  }
}

class _Splash extends StatelessWidget {
  const _Splash();

  @override
  Widget build(BuildContext context) {
    final HeloPalette p = HeloPalette.of(context);
    return Scaffold(
      body: Center(
        child: Column(mainAxisSize: MainAxisSize.min, children: <Widget>[
          Icon(Icons.lock_rounded, size: 44, color: p.accent),
          const SizedBox(height: 16),
          const Text('HELO', style: TextStyle(fontSize: 26, fontWeight: FontWeight.w800, letterSpacing: 4)),
          const SizedBox(height: 8),
          Text('Unlocking key material…', style: TextStyle(color: p.textFaint, fontSize: 12)),
        ]),
      ),
    );
  }
}

class _BootError extends StatelessWidget {
  const _BootError({required this.message, required this.onReset});
  final String message;
  final VoidCallback onReset;

  @override
  Widget build(BuildContext context) {
    final HeloPalette p = HeloPalette.of(context);
    return Scaffold(
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(28),
          child: Column(mainAxisSize: MainAxisSize.min, children: <Widget>[
            Icon(Icons.gpp_bad_outlined, size: 40, color: p.danger),
            const SizedBox(height: 14),
            Text(message, textAlign: TextAlign.center),
            const SizedBox(height: 8),
            Text(
              'It is not repaired automatically: corrupt key material is treated as untrusted. '
              'Resetting destroys it and starts over.',
              textAlign: TextAlign.center,
              style: TextStyle(color: p.textFaint, fontSize: 12),
            ),
            const SizedBox(height: 20),
            OutlinedButton(onPressed: onReset, child: Text('Reset this device', style: TextStyle(color: p.danger))),
          ]),
        ),
      ),
    );
  }
}
