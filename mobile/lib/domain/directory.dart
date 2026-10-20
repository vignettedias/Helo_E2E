/// Username → devices, with identity pinning.
///
/// The relay asserts which devices belong to which username; that binding is
/// as trustworthy as the relay (the same model as phone-number messengers).
/// What this class adds is CONSISTENCY: each device's identity key is pinned
/// the first time it is seen, and a later different identity for the same
/// device id is never silently accepted. The relay itself refuses identity
/// swaps under an existing device id, so a mismatch here means the relay is
/// misbehaving — the device is marked conflicted and nothing is encrypted to
/// it. Whether the binding is correct in the first place is what safety
/// numbers verify.
library;

import '../crypto/identity.dart';
import '../data/relay_client.dart';

class DevicePin {
  DevicePin({
    required this.deviceId,
    required this.username,
    required this.identity,
    required this.firstSeen,
    this.verified = false,
    this.conflict = false,
    this.active = true,
  });

  final String deviceId;
  final String username;
  final IdentityPublic identity;
  final DateTime firstSeen;

  /// The user compared safety numbers for this device and marked it verified.
  bool verified;

  /// The relay later reported a DIFFERENT identity for this device id.
  bool conflict;

  /// Listed by the relay at the last lookup (revoked devices drop out).
  bool active;

  Map<String, Object?> toJson() => <String, Object?>{
        'device': deviceId,
        'user': username,
        'identity': identity.toJson(),
        'first_seen': firstSeen.millisecondsSinceEpoch,
        if (verified) 'verified': true,
        if (conflict) 'conflict': true,
        if (!active) 'inactive': true,
      };

  static DevicePin fromJson(Map<String, dynamic> m) => DevicePin(
        deviceId: m['device']! as String,
        username: m['user']! as String,
        identity: IdentityPublic.fromJson(m['identity']! as Map<String, dynamic>),
        firstSeen: DateTime.fromMillisecondsSinceEpoch(m['first_seen']! as int),
        verified: m['verified'] == true,
        conflict: m['conflict'] == true,
        active: m['inactive'] != true,
      );
}

class DirectoryLookup {
  const DirectoryLookup(this.devices, {this.added = const <DevicePin>[],
      this.conflicts = const <DevicePin>[]});

  /// Active, non-conflicted devices: the ones it is safe to encrypt to.
  final List<DevicePin> devices;

  /// Devices seen for the first time in this lookup (excluding the very
  /// first lookup of a user), so the UI can announce "X added a device".
  final List<DevicePin> added;

  /// Devices whose identity disagrees with the pinned one.
  final List<DevicePin> conflicts;
}

class Directory {
  Directory(this.relay);

  final RelayClient relay;
  final Map<String, DevicePin> pins = <String, DevicePin>{};
  final Map<String, DateTime> _fetchedAt = <String, DateTime>{};

  static const Duration ttl = Duration(minutes: 2);

  DevicePin? pin(String deviceId) => pins[deviceId];

  List<DevicePin> devicesOf(String username) => pins.values
      .where((DevicePin p) => p.username == username && p.active && !p.conflict)
      .toList();

  List<DevicePin> allDevicesOf(String username) =>
      pins.values.where((DevicePin p) => p.username == username).toList();

  /// Resolve [username] to its devices, consulting the relay when the cached
  /// view is older than [ttl] or [refresh] is set.
  Future<DirectoryLookup> lookup(String username, {bool refresh = false}) async {
    final DateTime? fetched = _fetchedAt[username];
    if (!refresh && fetched != null && DateTime.now().difference(fetched) < ttl) {
      return DirectoryLookup(devicesOf(username));
    }
    final bool firstLookup = allDevicesOf(username).isEmpty;
    final DirectoryEntry entry = await relay.lookupUser(username);
    final List<DevicePin> added = <DevicePin>[];
    final List<DevicePin> conflicts = <DevicePin>[];
    final Set<String> listed = <String>{};

    for (final DirectoryDevice d in entry.devices) {
      final IdentityPublic identity;
      try {
        identity = IdentityPublic.fromJson(d.identity);
        // A device whose own identity binding does not verify is unusable,
        // whatever the relay says.
        await identity.verifyBinding();
      } on Object {
        continue;
      }
      listed.add(d.deviceId);
      final DevicePin? existing = pins[d.deviceId];
      if (existing == null) {
        final DevicePin pin = DevicePin(
          deviceId: d.deviceId,
          username: entry.username,
          identity: identity,
          firstSeen: DateTime.now(),
        );
        pins[d.deviceId] = pin;
        if (!firstLookup) added.add(pin);
      } else if (existing.username != entry.username ||
          !_same(existing.identity, identity)) {
        existing.conflict = true;
        conflicts.add(existing);
      } else {
        existing.active = true;
      }
    }
    for (final DevicePin p in allDevicesOf(entry.username)) {
      if (!listed.contains(p.deviceId)) p.active = false;
    }
    _fetchedAt[entry.username] = DateTime.now();
    return DirectoryLookup(devicesOf(entry.username), added: added, conflicts: conflicts);
  }

  static bool _same(IdentityPublic a, IdentityPublic b) {
    final List<int> x = a.encode();
    final List<int> y = b.encode();
    if (x.length != y.length) return false;
    for (int i = 0; i < x.length; i++) {
      if (x[i] != y[i]) return false;
    }
    return true;
  }

  bool matchesPin(String deviceId, IdentityPublic identity) {
    final DevicePin? p = pins[deviceId];
    return p != null && !p.conflict && _same(p.identity, identity);
  }

  List<Map<String, Object?>> toJson() => pins.values.map((DevicePin p) => p.toJson()).toList();

  void load(Object? json) {
    if (json is! List<Object?>) return;
    for (final Object? raw in json) {
      if (raw is Map<String, dynamic>) {
        final DevicePin p = DevicePin.fromJson(raw);
        pins[p.deviceId] = p;
      }
    }
  }
}
