/// The relay address is user-settable on a packaged app, so what it accepts
/// and what it warns about both matter.
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:helo/data/relay_address.dart';

void main() {
  test('accepts an origin and drops a trailing slash', () {
    expect(normaliseRelayUrl('http://192.168.1.20:8443'), 'http://192.168.1.20:8443');
    expect(normaliseRelayUrl('  https://relay.example.com/  '), 'https://relay.example.com');
    expect(normaliseRelayUrl('http://10.0.2.2:8443/'), 'http://10.0.2.2:8443');
  });

  test('refuses anything that is not a bare origin', () {
    for (final String bad in <String>[
      '', '   ', 'relay.example.com', 'ftp://host', 'http://', 'javascript:alert(1)',
      'http://host/path', 'http://host/?x=1', 'http://host/#f', 'http://user:pw@host',
      'http://${'h' * 300}',
    ]) {
      expect(normaliseRelayUrl(bad), isNull, reason: bad);
    }
  });

  test('warns only when cleartext actually crosses a network', () {
    expect(relayTransportIsExposed('http://192.168.1.20:8443'), isTrue);
    expect(relayTransportIsExposed('http://helo.example.com:8443'), isTrue);
    expect(relayTransportIsExposed('http://localhost:8443'), isFalse);
    expect(relayTransportIsExposed('http://127.0.0.1:8443'), isFalse);
    expect(relayTransportIsExposed('http://10.0.2.2:8443'), isFalse, reason: 'emulator loopback');
    expect(relayTransportIsExposed('https://192.168.1.20:5000'), isFalse);
  });
}
