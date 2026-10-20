/// Decrypted audio/video handed to the platform player, and recordings read
/// back from the platform recorder.
///
/// Players cannot read bytes from memory on every platform, so:
///   * web: the bytes become a Blob URL (memory only), revoked on dispose;
///   * mobile/desktop: the bytes are written to a temporary file that is
///     deleted on dispose. This is a short-lived PLAINTEXT copy on disk while
///     the item plays; it is documented in PRIVACY.md.
library;

export 'playable_media_io.dart' if (dart.library.js_interop) 'playable_media_web.dart';
