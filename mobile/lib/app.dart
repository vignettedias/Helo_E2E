/// Application root: dependency wiring and routing.
library;

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

import 'data/relay_client.dart';
import 'domain/session_manager.dart';
import 'storage/crypto_storage.dart';
import 'ui/screens/chat_list_screen.dart';
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
    return page.scheme == 'https'
        ? 'https://${page.host}'
        : 'http://${page.host}:8443';
  }
  if (defaultTargetPlatform == TargetPlatform.android) {
    return 'http://10.0.2.2:8443';
  }
  return 'http://localhost:8443';
}

/// Widest the app renders. On a desktop browser the UI sits in a centred
/// column rather than stretching chat bubbles across the whole screen.
const double _maxAppWidth = 560;

class HeloApp extends StatefulWidget {
  const HeloApp({super.key});

  @override
  State<HeloApp> createState() => _HeloAppState();
}

class _HeloAppState extends State<HeloApp> {
  late final CryptoStorage _storage;
  late final RelayClient _relay;
  SessionManager? _manager;
  bool _ready = false;
  String? _bootError;

  @override
  void initState() {
    super.initState();
    _storage = PlatformCryptoStorage();
    _relay = RelayClient(baseUrl: relayUrl);
    _bootstrap();
  }

  Future<void> _bootstrap() async {
    try {
      final String? deviceId = await _readString(StorageKeys.deviceId);
      if (deviceId != null) {
        final SessionManager manager = SessionManager(
          storage: _storage,
          relay: _relay,
          deviceId: deviceId,
        );
        if (await manager.restore()) _adopt(manager);
      }
    } catch (_) {
      // Stored state that cannot be read is not repaired or guessed at. The
      // user is told, and can reset the device to start cleanly.
      _bootError = 'Stored key material could not be read.';
    }
    if (mounted) setState(() => _ready = true);
  }

  Future<String?> _readString(String key) async {
    final List<int>? value = await _storage.get(key);
    return value == null ? null : String.fromCharCodes(value);
  }

  void _adopt(SessionManager manager) {
    manager.onReset = () {
      if (mounted) setState(() => _manager = null);
      manager.dispose();
    };
    _manager = manager;
  }

  void _onRegistered(SessionManager manager) => setState(() => _adopt(manager));

  Future<void> _wipeAfterBootError() async {
    await _storage.wipeAll();
    setState(() => _bootError = null);
  }

  @override
  void dispose() {
    _manager?.dispose();
    _relay.close();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Helo',
      debugShowCheckedModeBanner: false,
      theme: heloTheme(),
      builder: (BuildContext context, Widget? child) => ColoredBox(
        color: HeloColors.backdrop,
        child: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: _maxAppWidth),
            child: DecoratedBox(
              decoration: BoxDecoration(
                border: MediaQuery.sizeOf(context).width > _maxAppWidth
                    ? const Border.symmetric(
                        vertical: BorderSide(color: HeloColors.border))
                    : null,
              ),
              child: child,
            ),
          ),
        ),
      ),
      home: !_ready
          ? const _Splash()
          : _bootError != null
              ? _BootError(message: _bootError!, onReset: _wipeAfterBootError)
              : _manager == null
                  ? OnboardingScreen(
                      storage: _storage,
                      relay: _relay,
                      onRegistered: _onRegistered,
                    )
                  : ChatListScreen(manager: _manager!),
    );
  }
}

class _Splash extends StatelessWidget {
  const _Splash();

  @override
  Widget build(BuildContext context) => const Scaffold(
        body: Center(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: <Widget>[
              Icon(Icons.lock_outline, size: 44, color: HeloColors.accent),
              SizedBox(height: 16),
              Text('helo', style: TextStyle(fontSize: 26, letterSpacing: 3)),
              SizedBox(height: 8),
              Text('unlocking key material',
                  style: TextStyle(color: HeloColors.textFaint, fontSize: 12)),
            ],
          ),
        ),
      );
}

class _BootError extends StatelessWidget {
  const _BootError({required this.message, required this.onReset});
  final String message;
  final VoidCallback onReset;

  @override
  Widget build(BuildContext context) => Scaffold(
        body: Center(
          child: Padding(
            padding: const EdgeInsets.all(28),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: <Widget>[
                const Icon(Icons.gpp_bad_outlined,
                    size: 40, color: HeloColors.danger),
                const SizedBox(height: 14),
                Text(message, textAlign: TextAlign.center),
                const SizedBox(height: 8),
                const Text(
                  'It is not repaired automatically: corrupt key material is '
                  'treated as untrusted. Resetting destroys it and starts over.',
                  textAlign: TextAlign.center,
                  style: TextStyle(color: HeloColors.textFaint, fontSize: 12),
                ),
                const SizedBox(height: 20),
                OutlinedButton(
                  style: OutlinedButton.styleFrom(
                    foregroundColor: HeloColors.danger,
                    side: const BorderSide(color: HeloColors.danger),
                  ),
                  onPressed: onReset,
                  child: const Text('Reset this device'),
                ),
              ],
            ),
          ),
        ),
      );
}
