/// Runs the REAL Node relay (backend/src/server.js) for client tests.
///
/// Client tests talk to the actual relay over real HTTP rather than a
/// hand-written fake, so they exercise the same API contract, validation,
/// authorisation and rate limits as production — and cannot drift from it.
/// Each harness owns a fresh database file, so a test can also stop and
/// restart the relay on the same data (relay-restart and offline scenarios).
library;

import 'dart:convert';
import 'dart:io';

import 'package:helo/data/relay_client.dart';
import 'package:helo/domain/messenger.dart';
import 'package:helo/storage/crypto_storage.dart';
import 'package:http/http.dart' as http;

const String testPassword = 'correct-horse-battery-staple';

class RelayHarness {
  RelayHarness._(this.port, this.dir);

  final int port;
  final Directory dir;
  Process? _process;

  String get baseUrl => 'http://127.0.0.1:$port';
  String get dbPath => '${dir.path}${Platform.pathSeparator}relay.db';

  static Future<RelayHarness> start() async {
    final ServerSocket probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final int port = probe.port;
    await probe.close();
    final RelayHarness h =
        RelayHarness._(port, await Directory.systemTemp.createTemp('helo-relay-test-'));
    await h.resume();
    return h;
  }

  /// (Re)start the relay process on the same port and database.
  Future<void> resume() async {
    _process = await Process.start(
      'node',
      <String>['../backend/src/server.js'],
      environment: <String, String>{'PORT': '$port', 'HOST': '127.0.0.1', 'DB_PATH': dbPath},
    );
    // Drain output so the child never blocks on a full pipe.
    _process!.stdout.listen((_) {});
    _process!.stderr.listen((_) {});
    for (int i = 0; i < 100; i++) {
      try {
        final http.Response r = await http.get(Uri.parse('$baseUrl/health'));
        if (r.statusCode == 200) return;
      } on Object {
        // not up yet
      }
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
    throw StateError('relay did not start');
  }

  /// Stop the relay process, keeping its database (simulates an outage).
  Future<void> pause() async {
    final Process? p = _process;
    if (p == null) return;
    p.kill();
    await p.exitCode;
    _process = null;
  }

  Future<void> dispose() async {
    await pause();
    try {
      dir.deleteSync(recursive: true);
    } on FileSystemException {
      // Windows may hold the WAL file briefly; the OS cleans temp dirs.
    }
  }

  RelayClient client() => RelayClient(baseUrl: baseUrl);

  /// Register a user with a fresh device and in-memory key storage.
  Future<(Messenger, CryptoStorage)> user(String name) async {
    final CryptoStorage storage = InMemoryCryptoStorageForTestsOnly();
    final Messenger m = await Messenger.register(
      storage: storage, relay: client(), username: name, password: testPassword);
    return (m, storage);
  }

  /// What relaunching the app does: fresh objects over the same storage.
  Future<Messenger> reopen(CryptoStorage storage) async {
    final Messenger? m = await Messenger.restore(storage: storage, relay: client());
    if (m == null) throw StateError('nothing to restore');
    return m;
  }

  /// Revoke one bearer token server-side while the client still holds it —
  /// exactly what expiry looks like to the client.
  Future<void> revokeToken(String token) async {
    await http.post(Uri.parse('$baseUrl/auth/logout'),
        headers: <String, String>{'Authorization': 'Bearer $token'});
  }

  Future<Map<String, dynamic>> getJson(String path, String token) async {
    final http.Response r = await http.get(Uri.parse('$baseUrl$path'),
        headers: <String, String>{'Authorization': 'Bearer $token'});
    return jsonDecode(r.body) as Map<String, dynamic>;
  }
}
