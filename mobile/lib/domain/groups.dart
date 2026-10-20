/// Group membership rules — a pure function, so every rule is unit-testable.
///
/// Groups use PAIRWISE FAN-OUT over the existing one-to-one sessions: there is
/// no group key and no group cryptography of our own. Consequences:
///
/// * A removed member is simply not encrypted to afterwards, so they cannot
///   read later messages — there is no shared key for them to keep.
/// * A new member receives nothing sent before they joined, because nothing
///   sent before was ever encrypted to them.
/// * Membership changes are authorised by WHO SENT THEM: the authenticated
///   sender must be an admin of the state the receiver currently holds.
///
/// Known limitation (documented, not hidden): a malicious ADMIN can send
/// different snapshots to different members (equivocation). Pairwise fan-out
/// has no mechanism to detect that; MLS (RFC 9420) would. See SECURITY_MODEL.md.
library;

import 'dart:convert';

import '../protocol/payload.dart';
import 'models.dart';

enum GroupDecision { accepted, unauthorized, stale, invalid }

class GroupChange {
  const GroupChange(this.decision, {this.state, this.added = const <String>[],
      this.removed = const <String>[], this.selfRemoved = false, this.reason});

  final GroupDecision decision;
  final GroupState? state;
  final List<String> added;
  final List<String> removed;
  final bool selfRemoved;
  final String? reason;

  bool get accepted => decision == GroupDecision.accepted;

  static GroupChange reject(GroupDecision d, String reason) => GroupChange(d, reason: reason);
}

/// Canonical form for the tie-break between two different snapshots with the
/// same version: every member orders them the same way, so all converge.
String _canonical(GroupSnapshot s) {
  final List<String> members = List<String>.of(s.members)..sort();
  final List<String> admins = List<String>.of(s.admins)..sort();
  return jsonEncode(<Object?>[s.version, s.name, members, admins, s.avatar?.length ?? 0]);
}

bool _newer(GroupSnapshot proposed, GroupState current) {
  if (proposed.version != current.version) return proposed.version > current.version;
  return _canonical(proposed).compareTo(_canonical(current.toSnapshot())) > 0;
}

/// The only legal result of [leaver] leaving [current].
GroupSnapshot leaveSnapshot(GroupState current, String leaver) {
  final List<String> members = current.members.where((String u) => u != leaver).toList();
  List<String> admins = current.admins.where((String u) => u != leaver).toList();
  // A group never ends up without an admin: the first remaining member in
  // sorted order is promoted — deterministic, so every member agrees.
  if (admins.isEmpty && members.isNotEmpty) admins = <String>[(List<String>.of(members)..sort()).first];
  return GroupSnapshot(
    gid: current.gid,
    version: current.version + 1,
    name: current.name,
    members: members,
    admins: admins,
    avatar: current.avatar,
  );
}

GroupChange applyGroupChange({
  required GroupState? current,
  required GroupOp op,
  required GroupSnapshot proposed,
  required String sender,
  required String me,
}) {
  switch (op) {
    case GroupOp.create:
      if (current != null) {
        return GroupChange.reject(GroupDecision.stale, 'group already exists');
      }
      if (proposed.version != 1) {
        return GroupChange.reject(GroupDecision.invalid, 'a new group starts at version 1');
      }
      if (!proposed.admins.contains(sender)) {
        return GroupChange.reject(GroupDecision.unauthorized, 'creator must be an admin');
      }
      if (!proposed.members.contains(me)) {
        return GroupChange.reject(GroupDecision.invalid, 'not addressed to a member');
      }
      return GroupChange(GroupDecision.accepted,
          state: GroupState.fromSnapshot(proposed),
          added: proposed.members.where((String u) => u != sender).toList());

    case GroupOp.update:
      if (current == null) {
        // Someone added after creation learns the group from an update. There
        // is no earlier state to authorise against, so the snapshot must name
        // the sender as an admin and this user as a member. (A forged
        // "group" made this way is just a new group its sender administers.)
        if (!proposed.admins.contains(sender) || !proposed.members.contains(me)) {
          return GroupChange.reject(GroupDecision.unauthorized, 'not a member of this group');
        }
        return GroupChange(GroupDecision.accepted,
            state: GroupState.fromSnapshot(proposed), added: <String>[me]);
      }
      if (current.removed) {
        // Re-added after removal: same rule as joining, plus a newer version.
        if (!proposed.admins.contains(sender) || !proposed.members.contains(me)) {
          return GroupChange.reject(GroupDecision.unauthorized, 'no longer a member of this group');
        }
        if (!_newer(proposed, current)) {
          return GroupChange.reject(GroupDecision.stale, 'older or equal group version');
        }
        return _accept(current, proposed, me);
      }
      // Authority comes from the state WE hold, never from the proposal.
      if (!current.admins.contains(sender)) {
        return GroupChange.reject(GroupDecision.unauthorized, 'only admins can change the group');
      }
      if (!_newer(proposed, current)) {
        return GroupChange.reject(GroupDecision.stale, 'older or equal group version');
      }
      return _accept(current, proposed, me);

    case GroupOp.leave:
      if (current == null || current.removed || !current.members.contains(sender)) {
        return GroupChange.reject(GroupDecision.unauthorized, 'leaver is not a member');
      }
      if (proposed.version <= current.version) {
        return GroupChange.reject(GroupDecision.stale, 'older or equal group version');
      }
      // A "leave" may ONLY remove its sender. Anything else in the snapshot
      // would let a non-admin smuggle a membership change through it.
      final GroupSnapshot expected = leaveSnapshot(current, sender);
      final bool exact = _sameMembers(proposed.members, expected.members) &&
          _sameMembers(proposed.admins, expected.admins) &&
          proposed.name == expected.name;
      if (!exact) {
        return GroupChange.reject(GroupDecision.unauthorized, 'a leave may only remove its sender');
      }
      return _accept(current, proposed, me);
  }
}

bool _sameMembers(List<String> a, List<String> b) =>
    a.length == b.length && a.toSet().containsAll(b);

GroupChange _accept(GroupState current, GroupSnapshot proposed, String me) {
  final List<String> added =
      proposed.members.where((String u) => !current.members.contains(u)).toList();
  final List<String> removed =
      current.members.where((String u) => !proposed.members.contains(u)).toList();
  final GroupState next = GroupState.fromSnapshot(proposed)
    ..removed = !proposed.members.contains(me);
  return GroupChange(GroupDecision.accepted,
      state: next, added: added, removed: removed, selfRemoved: next.removed);
}
