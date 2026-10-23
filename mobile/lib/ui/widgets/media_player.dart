/// In-app playback of end-to-end encrypted audio, voice and video attachments.
///
/// Nothing is fetched or decrypted until the user taps play. The decrypted
/// media lives in a [PlayableMedia] that is released when the widget goes away.
library;

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:video_player/video_player.dart';

import '../../domain/messenger.dart';
import '../../media/playable_media.dart';
import '../../protocol/payload.dart';
import '../format.dart';
import '../theme.dart';

String playTime(Duration d) {
  final int s = d.inSeconds;
  return '${s ~/ 60}:${(s % 60).toString().padLeft(2, '0')}';
}

/// Loads, decrypts and opens an attachment for playback, once.
class _MediaLoader {
  _MediaLoader(this.messenger, this.ref);

  final Messenger messenger;
  final AttachmentRef ref;
  PlayableMedia? media;
  Future<VideoPlayerController>? _opening;

  Future<VideoPlayerController> open() => _opening ??= () async {
        final PlayableMedia m = await openPlayableMedia(await messenger.loadAttachment(ref), ref.mime);
        media = m;
        await m.controller.initialize();
        return m.controller;
      }();

  Future<void> dispose() async => media?.dispose();
}

String _failure(Object e) {
  final String s = e.toString();
  if (s.contains('AuthenticationError')) return 'failed integrity checks';
  if (s.contains('RelayException')) return 'download failed';
  return 'cannot be played on this device';
}

// ------------------------------------------------------------------- audio

class AudioAttachmentPlayer extends StatefulWidget {
  const AudioAttachmentPlayer({required this.messenger, required this.ref, this.onSave, super.key});

  final Messenger messenger;
  final AttachmentRef ref;
  final VoidCallback? onSave;

  @override
  State<AudioAttachmentPlayer> createState() => _AudioAttachmentPlayerState();
}

class _AudioAttachmentPlayerState extends State<AudioAttachmentPlayer> {
  late final _MediaLoader _loader = _MediaLoader(widget.messenger, widget.ref);
  VideoPlayerController? _c;
  bool _loading = false;
  String? _error;

  @override
  void dispose() {
    _c?.removeListener(_tick);
    unawaited(_loader.dispose());
    super.dispose();
  }

  void _tick() {
    if (mounted) setState(() {});
  }

  Future<void> _toggle() async {
    if (_c == null) {
      setState(() => _loading = true);
      try {
        final VideoPlayerController c = await _loader.open();
        if (!mounted) return;
        c.addListener(_tick);
        setState(() => _c = c);
      } on Object catch (e) {
        if (mounted) setState(() => _error = _failure(e));
        return;
      } finally {
        if (mounted) setState(() => _loading = false);
      }
    }
    final VideoPlayerController c = _c!;
    if (c.value.isPlaying) {
      await c.pause();
    } else {
      if (c.value.position >= c.value.duration) await c.seekTo(Duration.zero);
      await c.play();
    }
  }

  @override
  Widget build(BuildContext context) {
    final HeloPalette p = HeloPalette.of(context);
    final AttachmentRef a = widget.ref;
    final VideoPlayerController? c = _c;
    final Duration total = c?.value.duration ??
        (a.durationMs != null ? Duration(milliseconds: a.durationMs!) : Duration.zero);
    final Duration pos = c?.value.position ?? Duration.zero;
    final double progress =
        total.inMilliseconds == 0 ? 0 : (pos.inMilliseconds / total.inMilliseconds).clamp(0.0, 1.0);
    final bool playing = c?.value.isPlaying ?? false;

    return Container(
      width: 270,
      padding: const EdgeInsets.fromLTRB(4, 6, 10, 6),
      decoration: BoxDecoration(
        color: p.background.withValues(alpha: 0.45),
        borderRadius: BorderRadius.circular(4),
        border: Border.all(color: p.border),
      ),
      child: Row(children: <Widget>[
        _loading
            ? const Padding(
                padding: EdgeInsets.all(12),
                child: SizedBox(width: 22, height: 22, child: CircularProgressIndicator(strokeWidth: 2)))
            : IconButton(
                tooltip: playing ? 'Pause' : 'Play',
                onPressed: _error == null ? _toggle : null,
                icon: Icon(playing ? Icons.pause_circle_filled_rounded : Icons.play_circle_fill_rounded,
                    size: 36, color: p.accent),
              ),
        Expanded(
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: <Widget>[
            Row(children: <Widget>[
              Icon(a.voice ? Icons.mic_rounded : Icons.audiotrack_rounded, size: 14, color: p.textFaint),
              const SizedBox(width: 4),
              Expanded(
                child: Text(a.voice ? 'Voice message' : a.name,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 12.5)),
              ),
            ]),
            const SizedBox(height: 6),
            SliderTheme(
              data: SliderTheme.of(context).copyWith(
                trackHeight: 3,
                thumbShape: const RoundSliderThumbShape(enabledThumbRadius: 6),
                overlayShape: SliderComponentShape.noOverlay,
              ),
              child: Slider(
                value: progress,
                onChanged: c == null
                    ? null
                    : (double v) => c.seekTo(Duration(milliseconds: (v * total.inMilliseconds).round())),
              ),
            ),
            const SizedBox(height: 4),
            Text(
              _error ?? '${playTime(c == null ? total : pos)}${c == null ? '' : ' / ${playTime(total)}'}'
                  ' · ${fileSize(a.size)}',
              style: TextStyle(fontSize: 11, color: _error == null ? p.textFaint : p.danger),
            ),
          ]),
        ),
        if (widget.onSave != null)
          IconButton(
            tooltip: 'Save',
            visualDensity: VisualDensity.compact,
            onPressed: widget.onSave,
            icon: Icon(Icons.download_rounded, size: 20, color: p.textSecondary),
          ),
      ]),
    );
  }
}

// ------------------------------------------------------------------- video

/// Opens a full player for a video attachment.
Future<void> showVideoPlayer(BuildContext context, Messenger messenger, AttachmentRef ref,
    {VoidCallback? onSave}) =>
    showDialog<void>(
      context: context,
      builder: (BuildContext ctx) => Dialog(
        backgroundColor: Colors.black,
        insetPadding: const EdgeInsets.all(16),
        child: _VideoPlayerView(messenger: messenger, ref: ref, onSave: onSave),
      ),
    );

class _VideoPlayerView extends StatefulWidget {
  const _VideoPlayerView({required this.messenger, required this.ref, this.onSave});

  final Messenger messenger;
  final AttachmentRef ref;
  final VoidCallback? onSave;

  @override
  State<_VideoPlayerView> createState() => _VideoPlayerViewState();
}

class _VideoPlayerViewState extends State<_VideoPlayerView> {
  late final _MediaLoader _loader = _MediaLoader(widget.messenger, widget.ref);
  late final Future<VideoPlayerController> _ready = _loader.open().then((VideoPlayerController c) {
    c.addListener(_tick);
    unawaited(c.play());
    return c;
  });

  void _tick() {
    if (mounted) setState(() {});
  }

  @override
  void dispose() {
    _loader.media?.controller.removeListener(_tick);
    unawaited(_loader.dispose());
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return ConstrainedBox(
      constraints: const BoxConstraints(maxWidth: 900, maxHeight: 700),
      child: FutureBuilder<VideoPlayerController>(
        future: _ready,
        builder: (BuildContext context, AsyncSnapshot<VideoPlayerController> snap) {
          final Widget top = Row(children: <Widget>[
            const SizedBox(width: 12),
            Expanded(
              child: Text(widget.ref.name,
                  maxLines: 1, overflow: TextOverflow.ellipsis, style: const TextStyle(color: Colors.white)),
            ),
            if (widget.onSave != null)
              IconButton(
                  tooltip: 'Save',
                  onPressed: widget.onSave,
                  icon: const Icon(Icons.download_rounded, color: Colors.white)),
            IconButton(
                tooltip: 'Close',
                onPressed: () => Navigator.pop(context),
                icon: const Icon(Icons.close_rounded, color: Colors.white)),
          ]);
          if (snap.hasError) {
            return Column(mainAxisSize: MainAxisSize.min, children: <Widget>[
              top,
              Padding(
                padding: const EdgeInsets.all(32),
                child: Text('This video ${_failure(snap.error!)}. You can still save it.',
                    style: const TextStyle(color: Colors.white70)),
              ),
            ]);
          }
          if (!snap.hasData) {
            return Column(mainAxisSize: MainAxisSize.min, children: <Widget>[
              top,
              const Padding(padding: EdgeInsets.all(48), child: CircularProgressIndicator()),
            ]);
          }
          final VideoPlayerController c = snap.data!;
          return Column(mainAxisSize: MainAxisSize.min, children: <Widget>[
            top,
            Flexible(
              child: AspectRatio(
                aspectRatio: c.value.aspectRatio == 0 ? 16 / 9 : c.value.aspectRatio,
                child: GestureDetector(
                  onTap: () => c.value.isPlaying ? c.pause() : c.play(),
                  child: VideoPlayer(c),
                ),
              ),
            ),
            VideoProgressIndicator(c, allowScrubbing: true, padding: const EdgeInsets.symmetric(vertical: 6)),
            Row(children: <Widget>[
              IconButton(
                tooltip: c.value.isPlaying ? 'Pause' : 'Play',
                onPressed: () => c.value.isPlaying ? c.pause() : c.play(),
                icon: Icon(c.value.isPlaying ? Icons.pause_rounded : Icons.play_arrow_rounded,
                    color: Colors.white),
              ),
              Text('${playTime(c.value.position)} / ${playTime(c.value.duration)}',
                  style: const TextStyle(color: Colors.white70, fontSize: 12)),
            ]),
          ]);
        },
      ),
    );
  }
}
