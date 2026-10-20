import 'dart:js_interop';
import 'dart:typed_data';

import 'package:cross_file/cross_file.dart';
import 'package:video_player/video_player.dart';
import 'package:web/web.dart' as web;

/// A player over in-memory media. Call [dispose] when done.
class PlayableMedia {
  PlayableMedia._(this.controller, this._url);

  final VideoPlayerController controller;
  final String _url;

  Future<void> dispose() async {
    await controller.dispose();
    web.URL.revokeObjectURL(_url);
  }
}

/// Wrap decrypted [bytes] for playback. The Blob URL never leaves this page.
Future<PlayableMedia> openPlayableMedia(Uint8List bytes, String mime) async {
  final web.Blob blob = web.Blob(<JSAny>[bytes.toJS].toJS, web.BlobPropertyBag(type: mime));
  final String url = web.URL.createObjectURL(blob);
  return PlayableMedia._(VideoPlayerController.networkUrl(Uri.parse(url)), url);
}

/// Where the recorder should write. On the web the recorder keeps the audio in
/// memory and the path is ignored.
Future<String> recordingPath(String extension) async => '';

/// Read what the recorder produced (a Blob URL on the web) and release it.
Future<Uint8List> takeRecording(String path) async {
  final Uint8List bytes = await XFile(path).readAsBytes();
  web.URL.revokeObjectURL(path);
  return bytes;
}
