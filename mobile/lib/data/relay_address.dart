/// Where this device should reach the relay, and how safe that path is.
///
/// A packaged app (an APK sideloaded onto a phone) cannot know the address of
/// a relay running on someone's laptop, so the address is settable and stored.
/// Anything typed by a user is validated here before it is used.
library;

/// Accept only a plain http/https origin: scheme, host, optional port. No
/// path, query, fragment or credentials — those would silently change which
/// endpoint every request hits.
String? normaliseRelayUrl(String input) {
  final String text = input.trim();
  if (text.isEmpty || text.length > 200) return null;
  final Uri? uri = Uri.tryParse(text);
  if (uri == null) return null;
  if (uri.scheme != 'http' && uri.scheme != 'https') return null;
  if (uri.host.isEmpty) return null;
  if (uri.userInfo.isNotEmpty) return null;
  if (uri.path.isNotEmpty && uri.path != '/') return null;
  if (uri.hasQuery || uri.hasFragment) return null;
  final String port = uri.hasPort ? ':${uri.port}' : '';
  return '${uri.scheme}://${uri.host}$port';
}

/// Hosts where plain HTTP never leaves the machine (or the emulator's loopback
/// bridge to it), so it exposes nothing to a network.
bool _isLocal(String host) =>
    host == 'localhost' || host == '127.0.0.1' || host == '::1' || host == '10.0.2.2';

/// True when traffic to this relay crosses a network WITHOUT TLS.
///
/// End-to-end encryption still protects message content, but on a cleartext
/// hop anyone on the same network can read the metadata (who talks to whom and
/// when) and, more seriously, capture the bearer tokens in the Authorization
/// header and act as that device.
bool relayTransportIsExposed(String url) {
  final Uri? uri = Uri.tryParse(url);
  if (uri == null) return false;
  return uri.scheme == 'http' && !_isLocal(uri.host);
}
