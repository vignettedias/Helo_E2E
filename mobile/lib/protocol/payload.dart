/// App payload: what travels INSIDE the end-to-end encryption.
///
/// Every message, reaction, edit, deletion, receipt, typing event, profile
/// update, timer change and group change is one of these, padded and then
/// encrypted with the Double Ratchet. The relay sees none of the fields below
/// — not even which kind of payload a ciphertext carries, because they all
/// pad into the same size buckets.
///
///     {"v":1, "id":"<32 hex>", "ts":<ms>, "k":"<kind>", "conv":{"t":"d"} | {"t":"g","gid":"…"}, …}
///
/// SECURITY RULE: the SENDER of a payload is never read from the payload. It is
/// the account the relay authenticated for the sending device, bound on first
/// contact to that device's identity key, which the session authenticates.
/// Fields like `reply.author` are display hints, never authority.
///
/// Decoding is strict: unknown kinds, wrong types and oversized fields are
/// rejected, so a malicious peer cannot smuggle state the client never
/// validated.
library;

import 'dart:convert';
import 'dart:typed_data';

import '../crypto/encoding.dart';
import '../crypto/errors.dart';
import '../crypto/padding.dart';

const int payloadVersion = 1;
const int maxBodyChars = 8000;
const int maxNameChars = 64;
const int maxEmojiChars = 16;
const int maxReceiptTargets = 200;
const int maxGroupMembers = 256;
const int maxInlineImageBytes = 48 * 1024;
const int maxAttachmentsPerMessage = 10;

enum PayloadKind { msg, react, edit, del, rcpt, typing, profile, timer, group, join }

enum ReceiptKind { delivered, read }

enum GroupOp { create, update, leave }

/// Which conversation a payload belongs to: the direct conversation with the
/// sender, or a group identified by a random 128-bit id.
class ConvRef {
  const ConvRef.direct() : gid = null;
  const ConvRef.group(String this.gid);

  final String? gid;
  bool get isGroup => gid != null;

  Map<String, Object?> toJson() =>
      gid == null ? <String, Object?>{'t': 'd'} : <String, Object?>{'t': 'g', 'gid': gid};

  static ConvRef fromJson(Object? raw) {
    if (raw is! Map<String, dynamic>) throw const InvalidEncodingError('conv must be an object');
    if (raw['t'] == 'd') return const ConvRef.direct();
    if (raw['t'] == 'g') return ConvRef.group(_hexId(raw['gid'], 'gid'));
    throw const InvalidEncodingError('unknown conversation type');
  }
}

class ReplyRef {
  const ReplyRef({required this.id, required this.author, required this.snippet});
  final String id;
  final String author;
  final String snippet;

  Map<String, Object?> toJson() =>
      <String, Object?>{'id': id, 'author': author, 'snippet': snippet};

  static ReplyRef fromJson(Object? raw) {
    final Map<String, dynamic> m = _obj(raw, 'reply');
    return ReplyRef(
      id: _hexId(m['id'], 'reply.id'),
      author: _str(m['author'], 'reply.author', maxNameChars),
      snippet: _str(m['snippet'], 'reply.snippet', 200),
    );
  }
}

/// Everything a recipient needs to fetch and decrypt one attachment. The key
/// exists ONLY here, inside the encrypted payload — never on the relay.
class AttachmentRef {
  const AttachmentRef({
    required this.id,
    required this.key,
    required this.digest,
    required this.size,
    required this.mime,
    required this.name,
    required this.chunkSize,
    this.voice = false,
    this.durationMs,
  });

  /// Longest voice message accepted from the wire (the recorder stops at 5 min).
  static const int maxVoiceMs = 10 * 60 * 1000;

  final String id;
  final Uint8List key;
  final Uint8List digest;
  final int size;
  final String mime;
  final String name;
  final int chunkSize;

  /// Recorded in the app as a voice message (shown as a voice note, not a file).
  final bool voice;

  /// Playback length as measured by the sender, if known. Display only: the
  /// player measures the real length itself.
  final int? durationMs;

  bool get isImage => mime.startsWith('image/');
  bool get isAudio => mime.startsWith('audio/');
  bool get isVideo => mime.startsWith('video/');

  Map<String, Object?> toJson() => <String, Object?>{
        'id': id,
        'key': b64e(key),
        'digest': b64e(digest),
        'size': size,
        'mime': mime,
        'name': name,
        'chunk': chunkSize,
        if (voice) 'voice': true,
        if (durationMs != null) 'dur': durationMs,
      };

  static AttachmentRef fromJson(Object? raw) {
    final Map<String, dynamic> m = _obj(raw, 'att');
    final Object? size = m['size'];
    final Object? chunk = m['chunk'];
    if (size is! int || size < 0 || chunk is! int || chunk < 1 || chunk > 1 << 20) {
      throw const InvalidEncodingError('attachment size fields are invalid');
    }
    final Object? voice = m['voice'];
    final Object? dur = m['dur'];
    if (voice != null && voice != true) throw const InvalidEncodingError('att.voice is invalid');
    if (dur != null && (dur is! int || dur < 0 || dur > maxVoiceMs)) {
      throw const InvalidEncodingError('att.dur is invalid');
    }
    final String mime = _str(m['mime'], 'att.mime', 100);
    if (voice == true && !mime.startsWith('audio/')) {
      throw const InvalidEncodingError('a voice message must be audio');
    }
    return AttachmentRef(
      id: _hexId(m['id'], 'att.id'),
      key: b64d(_str(m['key'], 'att.key', 64), expectLen: 32),
      digest: b64d(_str(m['digest'], 'att.digest', 64), expectLen: 32),
      size: size,
      mime: mime,
      name: _str(m['name'], 'att.name', 200),
      chunkSize: chunk,
      voice: voice == true,
      durationMs: dur as int?,
    );
  }
}

/// A complete group state snapshot. Changes always carry the WHOLE state with
/// a higher version, so every member converges on the same state regardless
/// of which intermediate updates they missed.
class GroupSnapshot {
  const GroupSnapshot({
    required this.gid,
    required this.version,
    required this.name,
    required this.members,
    required this.admins,
    this.avatar,
  });

  final String gid;
  final int version;
  final String name;
  final List<String> members;
  final List<String> admins;
  final Uint8List? avatar;

  Map<String, Object?> toJson() => <String, Object?>{
        'gid': gid,
        'ver': version,
        'name': name,
        'members': members,
        'admins': admins,
        if (avatar != null) 'avatar': b64e(avatar!),
      };

  static GroupSnapshot fromJson(Object? raw) {
    final Map<String, dynamic> m = _obj(raw, 'group');
    final Object? ver = m['ver'];
    if (ver is! int || ver < 1) throw const InvalidEncodingError('group version invalid');
    final List<String> members = _usernames(m['members'], 'members');
    final List<String> admins = _usernames(m['admins'], 'admins');
    if (members.isEmpty || members.length > maxGroupMembers) {
      throw const InvalidEncodingError('group member list invalid');
    }
    if (!admins.every(members.contains)) {
      throw const InvalidEncodingError('every admin must be a member');
    }
    final Object? avatar = m['avatar'];
    return GroupSnapshot(
      gid: _hexId(m['gid'], 'gid'),
      version: ver,
      name: _str(m['name'], 'name', maxNameChars),
      members: members,
      admins: admins,
      avatar: avatar == null ? null : _image(avatar),
    );
  }
}

class AppPayload {
  AppPayload({
    required this.id,
    required this.timestampMs,
    required this.kind,
    this.conv,
    this.body,
    this.reply,
    this.attachments = const <AttachmentRef>[],
    this.forwarded = false,
    this.viewOnce = false,
    this.expireSeconds,
    this.target,
    this.emoji,
    this.receiptKind,
    this.targets = const <String>[],
    this.typingOn,
    this.displayName,
    this.avatar,
    this.timerSeconds,
    this.groupOp,
    this.group,
    this.inviteSecret,
  });

  final String id;
  final int timestampMs;
  final PayloadKind kind;
  final ConvRef? conv;

  // msg / edit
  final String? body;
  final ReplyRef? reply;
  final List<AttachmentRef> attachments;
  final bool forwarded;

  /// Burn after reading: the receiver shows it once, then erases it locally.
  /// Honest limits: this is a request the receiving CLIENT honours. It cannot
  /// stop a screenshot, a photograph, or a modified client.
  final bool viewOnce;
  final int? expireSeconds;

  // react / edit / del
  final String? target;
  final String? emoji;

  // rcpt
  final ReceiptKind? receiptKind;
  final List<String> targets;

  // typing
  final bool? typingOn;

  // join: the secret of a group invite link, sent only to the admin who made it
  final String? inviteSecret;

  // profile
  final String? displayName;
  final Uint8List? avatar;

  // timer
  final int? timerSeconds;

  // group
  final GroupOp? groupOp;
  final GroupSnapshot? group;

  Map<String, Object?> toJson() => <String, Object?>{
        'v': payloadVersion,
        'id': id,
        'ts': timestampMs,
        'k': kind.name,
        if (conv != null) 'conv': conv!.toJson(),
        if (body != null) 'body': body,
        if (reply != null) 'reply': reply!.toJson(),
        if (attachments.isNotEmpty)
          'att': attachments.map((AttachmentRef a) => a.toJson()).toList(),
        if (forwarded) 'fwd': true,
        if (viewOnce) 'once': true,
        if (expireSeconds != null) 'exp': expireSeconds,
        if (target != null) 'target': target,
        if (emoji != null) 'emoji': emoji,
        if (receiptKind != null) 'kind': receiptKind!.name,
        if (targets.isNotEmpty) 'targets': targets,
        if (typingOn != null) 'on': typingOn,
        if (displayName != null) 'name': displayName,
        if (avatar != null) 'avatar': b64e(avatar!),
        if (timerSeconds != null) 'seconds': timerSeconds,
        if (groupOp != null) 'op': groupOp!.name,
        if (group != null) 'group': group!.toJson(),
        if (inviteSecret != null) 'secret': inviteSecret,
      };

  /// JSON → padded plaintext ready for the ratchet.
  Uint8List encode([PaddingPolicy policy = defaultPaddingPolicy]) =>
      pad(utf8.encode(jsonEncode(toJson())), policy);

  /// Padded plaintext → validated payload. Throws [InvalidEncodingError] on
  /// anything malformed; never returns a half-validated object.
  static AppPayload decode(Uint8List padded) {
    final Object? raw;
    try {
      raw = jsonDecode(utf8.decode(unpad(padded)));
    } on FormatException {
      throw const InvalidEncodingError('payload is not valid UTF-8 JSON');
    }
    final Map<String, dynamic> m = _obj(raw, 'payload');
    if (m['v'] != payloadVersion) throw const InvalidEncodingError('unsupported payload version');
    final Object? ts = m['ts'];
    if (ts is! int) throw const InvalidEncodingError('payload timestamp missing');
    final PayloadKind kind = PayloadKind.values.firstWhere(
      (PayloadKind k) => k.name == m['k'],
      orElse: () => throw const InvalidEncodingError('unknown payload kind'),
    );
    final String id = _hexId(m['id'], 'id');
    final ConvRef? conv = m.containsKey('conv') ? ConvRef.fromJson(m['conv']) : null;
    if (kind != PayloadKind.profile && conv == null) {
      throw const InvalidEncodingError('payload lacks a conversation');
    }

    switch (kind) {
      case PayloadKind.msg:
        final Object? att = m['att'];
        final List<AttachmentRef> atts = att == null
            ? const <AttachmentRef>[]
            : _list(att, 'att', maxAttachmentsPerMessage).map(AttachmentRef.fromJson).toList();
        // An attachment without a caption is sent with an empty body; only a
        // message with neither text nor attachments is empty.
        final String body =
            m['body'] == null ? '' : _str(m['body'], 'body', maxBodyChars, allowEmpty: true);
        if (body.isEmpty && atts.isEmpty) throw const InvalidEncodingError('empty message');
        final Object? exp = m['exp'];
        final Object? once = m['once'];
        if (once != null && once != true) throw const InvalidEncodingError('once is invalid');
        return AppPayload(
          id: id, timestampMs: ts, kind: kind, conv: conv,
          body: body,
          reply: m['reply'] == null ? null : ReplyRef.fromJson(m['reply']),
          attachments: atts,
          forwarded: m['fwd'] == true,
          viewOnce: once == true,
          expireSeconds: exp is int && exp > 0 ? exp : null,
        );
      case PayloadKind.react:
        return AppPayload(
          id: id, timestampMs: ts, kind: kind, conv: conv,
          target: _hexId(m['target'], 'target'),
          emoji: _str(m['emoji'], 'emoji', maxEmojiChars, allowEmpty: true),
        );
      case PayloadKind.edit:
        return AppPayload(
          id: id, timestampMs: ts, kind: kind, conv: conv,
          target: _hexId(m['target'], 'target'),
          body: _str(m['body'], 'body', maxBodyChars),
        );
      case PayloadKind.del:
        return AppPayload(
          id: id, timestampMs: ts, kind: kind, conv: conv,
          target: _hexId(m['target'], 'target'),
        );
      case PayloadKind.rcpt:
        final ReceiptKind rk = ReceiptKind.values.firstWhere(
          (ReceiptKind r) => r.name == m['kind'],
          orElse: () => throw const InvalidEncodingError('unknown receipt kind'),
        );
        return AppPayload(
          id: id, timestampMs: ts, kind: kind, conv: conv,
          receiptKind: rk,
          targets: _list(m['targets'], 'targets', maxReceiptTargets)
              .map((Object? t) => _hexId(t, 'targets'))
              .toList(),
        );
      case PayloadKind.typing:
        final Object? on = m['on'];
        if (on is! bool) throw const InvalidEncodingError('typing flag missing');
        return AppPayload(id: id, timestampMs: ts, kind: kind, conv: conv, typingOn: on);
      case PayloadKind.profile:
        final Object? avatar = m['avatar'];
        return AppPayload(
          id: id, timestampMs: ts, kind: kind,
          displayName: _str(m['name'], 'name', maxNameChars, allowEmpty: true),
          avatar: avatar == null ? null : _image(avatar),
        );
      case PayloadKind.timer:
        final Object? seconds = m['seconds'];
        if (seconds is! int || seconds < 0 || seconds > 365 * 24 * 3600) {
          throw const InvalidEncodingError('timer out of range');
        }
        return AppPayload(id: id, timestampMs: ts, kind: kind, conv: conv, timerSeconds: seconds);
      case PayloadKind.group:
        final GroupOp op = GroupOp.values.firstWhere(
          (GroupOp o) => o.name == m['op'],
          orElse: () => throw const InvalidEncodingError('unknown group op'),
        );
        final GroupSnapshot snapshot = GroupSnapshot.fromJson(m['group']);
        if (!conv!.isGroup || conv.gid != snapshot.gid) {
          throw const InvalidEncodingError('group payload names a different group');
        }
        return AppPayload(
            id: id, timestampMs: ts, kind: kind, conv: conv, groupOp: op, group: snapshot);
      case PayloadKind.join:
        if (!conv!.isGroup) throw const InvalidEncodingError('a join request names a group');
        return AppPayload(
            id: id, timestampMs: ts, kind: kind, conv: conv, inviteSecret: _hexId(m['secret'], 'secret'));
    }
  }
}

// ----------------------------------------------------------- validation

Map<String, dynamic> _obj(Object? raw, String field) {
  if (raw is! Map<String, dynamic>) throw InvalidEncodingError('$field must be an object');
  return raw;
}

List<Object?> _list(Object? raw, String field, int max) {
  if (raw is! List<Object?> || raw.length > max) {
    throw InvalidEncodingError('$field must be a list of at most $max items');
  }
  return raw;
}

String _str(Object? raw, String field, int maxChars, {bool allowEmpty = false}) {
  if (raw is! String || raw.length > maxChars || (!allowEmpty && raw.isEmpty)) {
    throw InvalidEncodingError('$field must be a string of at most $maxChars characters');
  }
  return raw;
}

final RegExp _hex128 = RegExp(r'^[0-9a-f]{32}$');
final RegExp _usernameRe = RegExp(r'^[a-z0-9][a-z0-9._-]{2,31}$');

String _hexId(Object? raw, String field) {
  if (raw is! String || !_hex128.hasMatch(raw)) {
    throw InvalidEncodingError('$field must be a 128-bit hex id');
  }
  return raw;
}

List<String> _usernames(Object? raw, String field) {
  final List<String> out = <String>[];
  for (final Object? u in _list(raw, field, maxGroupMembers)) {
    if (u is! String || !_usernameRe.hasMatch(u)) {
      throw InvalidEncodingError('$field contains an invalid username');
    }
    if (!out.contains(u)) out.add(u);
  }
  return out;
}

Uint8List _image(Object? raw) {
  final Uint8List bytes = b64d(_str(raw, 'avatar', maxInlineImageBytes * 4 ~/ 3 + 4));
  if (bytes.length > maxInlineImageBytes) throw const InvalidEncodingError('image too large');
  return bytes;
}

/// A fresh random 128-bit id, hex encoded (message ids, group ids).
String newId(Uint8List Function(int) randomBytes) {
  final Uint8List b = randomBytes(16);
  final StringBuffer sb = StringBuffer();
  for (final int x in b) {
    sb.write(x.toRadixString(16).padLeft(2, '0'));
  }
  return sb.toString();
}
