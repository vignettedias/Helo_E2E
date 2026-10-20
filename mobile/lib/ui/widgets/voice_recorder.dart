/// Records a voice message. Recording happens on the device; the result is
/// handed to the caller, which encrypts it like any other attachment.
library;

import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:record/record.dart';

import '../../media/playable_media.dart';
import '../theme.dart';
import 'media_player.dart' show playTime;

/// Recordings stop on their own at this length.
const Duration maxVoiceLength = Duration(minutes: 5);

/// Shorter than this is treated as an accidental tap and discarded.
const Duration minVoiceLength = Duration(milliseconds: 500);

/// A finished recording.
class VoiceClip {
  const VoiceClip(this.bytes, this.mime, this.extension, this.duration);

  final Uint8List bytes;
  final String mime;
  final String extension;
  final Duration duration;
}

/// The format to record in: AAC (.m4a) wherever the platform can encode it,
/// because every platform can play it; otherwise 16 kHz mono WAV (Chrome and
/// Firefox can only produce WebM/Opus or WAV, and iPhones cannot play WebM).
/// WAV costs ~32 KB/s: 5 minutes ≈ 9.6 MB, inside the 24 MB attachment limit.
Future<(RecordConfig, String mime, String ext)> chooseVoiceFormat(AudioRecorder r) async {
  if (await r.isEncoderSupported(AudioEncoder.aacLc)) {
    return (const RecordConfig(encoder: AudioEncoder.aacLc, numChannels: 1, bitRate: 48000), 'audio/mp4', 'm4a');
  }
  return (const RecordConfig(encoder: AudioEncoder.wav, numChannels: 1, sampleRate: 16000), 'audio/wav', 'wav');
}

class VoiceRecorderBar extends StatefulWidget {
  const VoiceRecorderBar({required this.onDone, required this.onCancel, super.key});

  /// Called with the finished clip when the user taps send.
  final Future<void> Function(VoiceClip clip) onDone;

  /// Called after the recording is discarded (or could not start); [reason]
  /// is shown to the user when present.
  final void Function(String? reason) onCancel;

  @override
  State<VoiceRecorderBar> createState() => _VoiceRecorderBarState();
}

class _VoiceRecorderBarState extends State<VoiceRecorderBar> {
  final AudioRecorder _rec = AudioRecorder();
  final Stopwatch _watch = Stopwatch();
  Timer? _ticker;
  StreamSubscription<Amplitude>? _level;
  double _amp = 0;
  String? _mime;
  String? _ext;
  bool _stopped = false;
  bool _sending = false;
  bool _finished = false;

  @override
  void initState() {
    super.initState();
    unawaited(_start());
  }

  @override
  void dispose() {
    _ticker?.cancel();
    unawaited(_level?.cancel());
    // Teardown must not throw: where the recorder never started (no plugin,
    // no microphone) these calls fail with the same error _start reported.
    if (!_finished) unawaited(_rec.cancel().catchError((Object _) {}));
    unawaited(_rec.dispose().catchError((Object _) {}));
    super.dispose();
  }

  Future<void> _start() async {
    try {
      if (!await _rec.hasPermission()) {
        _finished = true;
        widget.onCancel('Microphone permission was not granted.');
        return;
      }
      final (RecordConfig config, String mime, String ext) = await chooseVoiceFormat(_rec);
      _mime = mime;
      _ext = ext;
      await _rec.start(config, path: await recordingPath(ext));
      _watch.start();
      _level = _rec
          .onAmplitudeChanged(const Duration(milliseconds: 150))
          .listen((Amplitude a) => _amp = ((a.current + 50) / 50).clamp(0.0, 1.0));
      _ticker = Timer.periodic(const Duration(milliseconds: 200), (_) {
        if (_watch.elapsed >= maxVoiceLength && !_stopped) {
          unawaited(_pause());
        }
        if (mounted) setState(() {});
      });
      if (mounted) setState(() {});
    } on Object {
      _finished = true;
      widget.onCancel('No microphone is available here.');
    }
  }

  Future<void> _pause() async {
    _watch.stop();
    _stopped = true;
    await _rec.pause();
  }

  Future<void> _discard() async {
    _finished = true;
    await _rec.cancel();
    widget.onCancel(null);
  }

  Future<void> _send() async {
    final Duration length = _watch.elapsed;
    setState(() => _sending = true);
    _watch.stop();
    final String? path = await _rec.stop();
    _finished = true;
    if (path == null || length < minVoiceLength) {
      widget.onCancel(length < minVoiceLength ? 'Too short — hold on a little longer.' : null);
      return;
    }
    final Uint8List bytes = await takeRecording(path);
    await widget.onDone(VoiceClip(bytes, _mime!, _ext!, length));
  }

  @override
  Widget build(BuildContext context) {
    final HeloPalette p = HeloPalette.of(context);
    final bool live = _mime != null && !_stopped;
    return Row(children: <Widget>[
      IconButton(
        tooltip: 'Discard',
        onPressed: _sending ? null : _discard,
        icon: Icon(Icons.delete_outline_rounded, color: p.danger),
      ),
      Icon(Icons.fiber_manual_record_rounded, size: 14, color: live ? p.danger : p.textFaint),
      const SizedBox(width: 6),
      Text(playTime(_watch.elapsed),
          style: const TextStyle(fontFeatures: <FontFeature>[FontFeature.tabularFigures()])),
      const SizedBox(width: 12),
      Expanded(
        child: _stopped
            ? Text('Limit reached (${maxVoiceLength.inMinutes} min). Send or discard.',
                style: TextStyle(color: p.textSecondary, fontSize: 12))
            : ClipRRect(
                borderRadius: BorderRadius.circular(4),
                child: LinearProgressIndicator(value: live ? _amp : null, minHeight: 6),
              ),
      ),
      const SizedBox(width: 6),
      IconButton.filled(
        tooltip: 'Send voice message',
        onPressed: _mime == null || _sending ? null : _send,
        icon: _sending
            ? const SizedBox(width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2))
            : const Icon(Icons.send_rounded, size: 20),
      ),
    ]);
  }
}
