import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:path_provider/path_provider.dart';
import 'package:video_player/video_player.dart';

/// A player over a temporary plaintext file. Call [dispose] when done: it
/// deletes the file.
class PlayableMedia {
  PlayableMedia._(this.controller, this._file);

  final VideoPlayerController controller;
  final File _file;

  Future<void> dispose() async {
    await controller.dispose();
    await _deleteQuietly(_file);
  }
}

Future<PlayableMedia> openPlayableMedia(Uint8List bytes, String mime) async {
  final File f = await _tempFile(_extensionFor(mime));
  await f.writeAsBytes(bytes, flush: true);
  return PlayableMedia._(VideoPlayerController.file(f), f);
}

Future<String> recordingPath(String extension) async => (await _tempFile(extension)).path;

/// Read the finished recording and delete the file it was written to.
Future<Uint8List> takeRecording(String path) async {
  final File f = File(path);
  final Uint8List bytes = await f.readAsBytes();
  await _deleteQuietly(f);
  return bytes;
}

Future<File> _tempFile(String extension) async {
  final Directory dir = await getTemporaryDirectory();
  final Random r = Random.secure();
  final String name = List<String>.generate(16, (_) => r.nextInt(16).toRadixString(16)).join();
  return File('${dir.path}${Platform.pathSeparator}helo-media-$name.$extension');
}

Future<void> _deleteQuietly(File f) async {
  try {
    if (await f.exists()) await f.delete();
  } on FileSystemException {
    // Already gone, or held by the OS briefly; the OS clears its temp dir.
  }
}

String _extensionFor(String mime) => switch (mime) {
      'audio/mp4' || 'audio/m4a' || 'audio/x-m4a' || 'audio/aac' => 'm4a',
      'audio/wav' || 'audio/x-wav' || 'audio/wave' => 'wav',
      'audio/mpeg' => 'mp3',
      'audio/ogg' => 'ogg',
      'audio/webm' => 'webm',
      'video/mp4' => 'mp4',
      'video/webm' => 'webm',
      'video/quicktime' => 'mov',
      _ => 'bin',
    };
