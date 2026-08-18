/// Application root: dependency wiring and routing.
library;

import 'package:flutter/material.dart';

import 'data/relay_client.dart';
import 'domain/session_manager.dart';
import 'storage/crypto_storage.dart';
import 'ui/screens/chat_list_screen.dart';
import 'ui/screens/onboarding_screen.dart';
import 'ui/theme.dart';

/// Relay endpoint. Override at build time:
///   flutter run --dart-define=HELO_RELAY_URL=https://relay.example.com
const String relayUrl = String.fromEnvironment(
  'HELO_RELAY_URL',
  defaultValue: 'http://10.0.2.2:8443', // Android emulator -> host machine
);

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

  @override
  void initState() {
    super.initState();
    _storage = PlatformCryptoStorage();
    _relay = RelayClient(baseUrl: relayUrl);
    _bootstrap();
  }

  Future<void> _bootstrap() async {
    final String? deviceId = await _readDeviceId();
    if (deviceId == null) {
      setState(() => _ready = true);
      return;
    }
    final SessionManager manager = SessionManager(
      storage: _storage,
      relay: _relay,
      deviceId: deviceId,
    );
    await manager.loadOrCreateIdentity();
    if (!mounted) return;
    setState(() {
      _manager = manager;
      _ready = true;
    });
  }

  Future<String?> _readDeviceId() async {
    final value = await _storage.get(StorageKeys.deviceId);
    if (value == null) return null;
    return String.fromCharCodes(value);
  }

  void _onRegistered(SessionManager manager) =>
      setState(() => _manager = manager);

  @override
  void dispose() {
    _manager?.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Helo',
      debugShowCheckedModeBanner: false,
      theme: heloTheme(),
      home: !_ready
          ? const _Splash()
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
