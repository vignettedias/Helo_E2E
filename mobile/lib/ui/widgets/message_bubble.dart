import 'dart:typed_data';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

import '../../domain/messenger.dart';
import '../../domain/models.dart';
import '../../protocol/payload.dart';
import '../format.dart';
import '../theme.dart';
import 'avatar.dart';
import 'media_player.dart';
import 'security_badges.dart';

class MessageBubble extends StatelessWidget {
  const MessageBubble({
    required this.messenger,
    required this.conversation,
    required this.message,
    required this.onActions,
    this.showAuthor = false,
    this.highlight = false,
    super.key,
  });

  final Messenger messenger;
  final Conversation conversation;
  final ChatMessage message;
  final void Function(ChatMessage) onActions;
  final bool showAuthor;
  final bool highlight;

  @override
  Widget build(BuildContext context) {
    final HeloPalette p = HeloPalette.of(context);
    final ChatMessage m = message;

    if (m.system) {
      return Center(
        child: Container(
          margin: const EdgeInsets.symmetric(vertical: 6, horizontal: 24),
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
          decoration: BoxDecoration(
            color: p.surfaceRaised,
            borderRadius: BorderRadius.circular(12),
          ),
          child: Text(m.body,
              textAlign: TextAlign.center,
              style: TextStyle(color: p.textSecondary, fontSize: 12)),
        ),
      );
    }

    final bool out = m.outgoing;
    final double maxWidth = MediaQuery.sizeOf(context).width.clamp(0, 1400) * 0.68;
    final Widget bubble = Container(
      constraints: BoxConstraints(maxWidth: maxWidth.clamp(220, 560)),
      padding: const EdgeInsets.fromLTRB(11, 8, 11, 6),
      decoration: BoxDecoration(
        color: highlight
            ? p.warning.withValues(alpha: 0.25)
            : (out ? p.bubbleOut : p.bubbleIn),
        borderRadius: BorderRadius.only(
          topLeft: const Radius.circular(16),
          topRight: const Radius.circular(16),
          bottomLeft: Radius.circular(out ? 16 : 4),
          bottomRight: Radius.circular(out ? 4 : 16),
        ),
        border: Border.all(color: out ? Colors.transparent : p.border),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: <Widget>[
          if (showAuthor && !out)
            Padding(
              padding: const EdgeInsets.only(bottom: 3),
              child: Text(messenger.labelOf(m.author),
                  style: TextStyle(
                      color: tintFor(m.author), fontWeight: FontWeight.w700, fontSize: 12.5)),
            ),
          if (m.forwarded && !m.deleted)
            Padding(
              padding: const EdgeInsets.only(bottom: 3),
              child: Row(mainAxisSize: MainAxisSize.min, children: <Widget>[
                Icon(Icons.shortcut_rounded, size: 13, color: p.textFaint),
                const SizedBox(width: 3),
                Text('Forwarded',
                    style: TextStyle(color: p.textFaint, fontSize: 11.5, fontStyle: FontStyle.italic)),
              ]),
            ),
          if (m.reply != null && !m.deleted) _ReplyQuote(messenger: messenger, reply: m.reply!),
          if (m.deleted)
            Row(mainAxisSize: MainAxisSize.min, children: <Widget>[
              Icon(Icons.block_rounded, size: 14, color: p.textFaint),
              const SizedBox(width: 5),
              Text('This message was deleted',
                  style: TextStyle(color: p.textFaint, fontStyle: FontStyle.italic)),
            ])
          else ...<Widget>[
            for (final AttachmentRef a in m.attachments)
              Padding(
                padding: const EdgeInsets.only(bottom: 4),
                child: AttachmentView(messenger: messenger, ref: a),
              ),
            if (m.body.isNotEmpty) Text(m.body, style: const TextStyle(fontSize: 14.5)),
          ],
          const SizedBox(height: 3),
          Row(
            mainAxisSize: MainAxisSize.min,
            children: <Widget>[
              if (m.expiresAt != null) ...<Widget>[
                Icon(Icons.timer_outlined, size: 11, color: p.textFaint),
                const SizedBox(width: 3),
              ],
              if (m.edited && !m.deleted)
                Text('edited · ', style: TextStyle(color: p.textFaint, fontSize: 10.5)),
              Text(clock(m.sentAt), style: TextStyle(color: p.textFaint, fontSize: 10.5)),
              if (out) ...<Widget>[
                const SizedBox(width: 4),
                StatusTicks(status: m.status, size: 14),
              ],
            ],
          ),
        ],
      ),
    );

    final Map<String, int> counts = <String, int>{};
    for (final String e in m.reactions.values) {
      counts[e] = (counts[e] ?? 0) + 1;
    }

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2, horizontal: 10),
      child: Column(
        crossAxisAlignment: out ? CrossAxisAlignment.end : CrossAxisAlignment.start,
        children: <Widget>[
          GestureDetector(
            behavior: HitTestBehavior.opaque,
            // Tap, long-press or right-click: the actions menu must be easy to
            // find on touch screens and desktops alike.
            onTap: () => onActions(m),
            onLongPress: () => onActions(m),
            onSecondaryTap: () => onActions(m),
            child: bubble,
          ),
          if (m.status == MessageStatus.failed && out)
            Padding(
              padding: const EdgeInsets.only(top: 2),
              child: InkWell(
                onTap: () => onActions(m),
                child: Text('Not sent — ${m.failureReason ?? 'tap for options'}',
                    style: TextStyle(color: p.danger, fontSize: 11.5)),
              ),
            ),
          if (counts.isNotEmpty)
            Transform.translate(
              offset: const Offset(0, -4),
              child: Container(
                margin: const EdgeInsets.symmetric(horizontal: 8),
                padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
                decoration: BoxDecoration(
                  color: p.surfaceRaised,
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: p.border),
                ),
                child: Text(
                  counts.entries
                      .map((MapEntry<String, int> e) => e.value > 1 ? '${e.key} ${e.value}' : e.key)
                      .join('  '),
                  style: const TextStyle(fontSize: 13),
                ),
              ),
            ),
        ],
      ),
    );
  }
}

class _ReplyQuote extends StatelessWidget {
  const _ReplyQuote({required this.messenger, required this.reply});
  final Messenger messenger;
  final ReplyRef reply;

  @override
  Widget build(BuildContext context) {
    final HeloPalette p = HeloPalette.of(context);
    return Container(
      margin: const EdgeInsets.only(bottom: 5),
      padding: const EdgeInsets.fromLTRB(8, 5, 8, 5),
      decoration: BoxDecoration(
        color: p.background.withValues(alpha: 0.5),
        borderRadius: BorderRadius.circular(8),
        border: Border(left: BorderSide(color: tintFor(reply.author), width: 3)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: <Widget>[
          Text(messenger.labelOf(reply.author),
              style: TextStyle(
                  color: tintFor(reply.author), fontSize: 12, fontWeight: FontWeight.w700)),
          Text(reply.snippet.isEmpty ? 'Attachment' : reply.snippet,
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(color: p.textSecondary, fontSize: 12.5)),
        ],
      ),
    );
  }
}

/// An encrypted attachment. Images are fetched, verified and decrypted to
/// display inline; other files show a card with a save button. Nothing is
/// fetched until shown, and the relay only ever serves ciphertext.
class AttachmentView extends StatefulWidget {
  const AttachmentView({required this.messenger, required this.ref, super.key});
  final Messenger messenger;
  final AttachmentRef ref;

  @override
  State<AttachmentView> createState() => _AttachmentViewState();
}

class _AttachmentViewState extends State<AttachmentView> {
  Future<Uint8List>? _bytes;
  bool _saving = false;

  @override
  void initState() {
    super.initState();
    final Uint8List? cached = widget.messenger.cachedAttachment(widget.ref.id);
    // Images up to 5 MB load automatically; anything else waits for a tap.
    if (cached != null) {
      _bytes = Future<Uint8List>.value(cached);
    } else if (widget.ref.isImage && widget.ref.size <= 5 * 1024 * 1024) {
      _bytes = widget.messenger.loadAttachment(widget.ref);
    }
  }

  Future<void> _save() async {
    setState(() => _saving = true);
    try {
      final Uint8List bytes = await (_bytes ??= widget.messenger.loadAttachment(widget.ref));
      await FilePicker.saveFile(fileName: widget.ref.name, bytes: bytes);
    } on Object catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(
            content: Text('Could not open the attachment: ${_reason(e)}')));
      }
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  String _reason(Object e) =>
      e.toString().contains('AuthenticationError') ? 'it failed integrity checks' : 'download failed';

  @override
  Widget build(BuildContext context) {
    final HeloPalette p = HeloPalette.of(context);
    final AttachmentRef a = widget.ref;
    if (a.isAudio) {
      return AudioAttachmentPlayer(messenger: widget.messenger, ref: a, onSave: _save);
    }
    if (a.isImage && _bytes != null) {
      return FutureBuilder<Uint8List>(
        future: _bytes,
        builder: (BuildContext context, AsyncSnapshot<Uint8List> snap) {
          if (snap.hasError) return _card(p, error: _reason(snap.error!));
          if (!snap.hasData) {
            return Container(
              width: 240,
              height: 160,
              alignment: Alignment.center,
              decoration: BoxDecoration(
                  color: p.surfaceRaised, borderRadius: BorderRadius.circular(10)),
              child: const SizedBox(
                  width: 22, height: 22, child: CircularProgressIndicator(strokeWidth: 2)),
            );
          }
          return GestureDetector(
            onTap: () => showDialog<void>(
              context: context,
              builder: (BuildContext ctx) => Dialog(
                backgroundColor: Colors.black,
                insetPadding: const EdgeInsets.all(16),
                child: Stack(children: <Widget>[
                  InteractiveViewer(child: Center(child: Image.memory(snap.data!))),
                  Positioned(
                    right: 4,
                    top: 4,
                    child: Row(children: <Widget>[
                      IconButton(
                          tooltip: 'Save',
                          onPressed: _save,
                          icon: const Icon(Icons.download_rounded, color: Colors.white)),
                      IconButton(
                          tooltip: 'Close',
                          onPressed: () => Navigator.pop(ctx),
                          icon: const Icon(Icons.close_rounded, color: Colors.white)),
                    ]),
                  ),
                ]),
              ),
            ),
            child: ClipRRect(
              borderRadius: BorderRadius.circular(10),
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 300, maxHeight: 320),
                child: Image.memory(snap.data!, fit: BoxFit.cover, gaplessPlayback: true),
              ),
            ),
          );
        },
      );
    }
    return _card(p);
  }

  Widget _card(HeloPalette p, {String? error}) {
    final AttachmentRef a = widget.ref;
    final IconData icon = a.isImage
        ? Icons.image_outlined
        : a.isAudio
            ? Icons.audiotrack_rounded
            : a.isVideo
                ? Icons.movie_outlined
                : a.mime == 'application/pdf'
                    ? Icons.picture_as_pdf_outlined
                    : Icons.insert_drive_file_outlined;
    return Container(
      width: 260,
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: p.background.withValues(alpha: 0.45),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: p.border),
      ),
      child: Row(children: <Widget>[
        Icon(icon, color: p.accent, size: 28),
        const SizedBox(width: 10),
        Expanded(
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: <Widget>[
            Text(a.name, maxLines: 1, overflow: TextOverflow.ellipsis,
                style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 13)),
            Text(error ?? '${fileSize(a.size)} · end-to-end encrypted',
                style: TextStyle(color: error == null ? p.textFaint : p.danger, fontSize: 11)),
          ]),
        ),
        _saving
            ? const SizedBox(width: 22, height: 22, child: CircularProgressIndicator(strokeWidth: 2))
            : IconButton(
                tooltip: a.isImage ? 'Show' : (a.isVideo ? 'Play' : 'Save'),
                icon: Icon(a.isImage
                    ? Icons.visibility_outlined
                    : (a.isVideo ? Icons.play_circle_outline_rounded : Icons.download_rounded)),
                onPressed: a.isImage
                    ? () => setState(() => _bytes = widget.messenger.loadAttachment(a))
                    : a.isVideo
                        ? () => showVideoPlayer(context, widget.messenger, a, onSave: _save)
                        : _save,
              ),
      ]),
    );
  }
}
