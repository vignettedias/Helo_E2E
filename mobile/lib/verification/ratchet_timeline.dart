/// The Double Ratchet, made visible: consecutive messages encrypted under the
/// same sender ratchet key form one "epoch"; a new key means a DH ratchet
/// step (fresh key material — the reason a stolen key does not unlock later
/// messages). Built only from WireInfo, i.e. what the relay already saw.
library;

import '../domain/models.dart';

class RatchetEpoch {
  RatchetEpoch(this.outgoing, this.dhHead, this.firstN);
  final bool outgoing;
  final String dhHead;
  final int firstN;
  int lastN = 0;
  int messages = 0;
}

List<RatchetEpoch> ratchetEpochs(Iterable<ChatMessage> messages) {
  final List<RatchetEpoch> out = <RatchetEpoch>[];
  for (final ChatMessage m in messages) {
    final WireInfo? w = m.wire;
    if (w == null || m.system) continue;
    final RatchetEpoch? last = out.isEmpty ? null : out.last;
    final RatchetEpoch e = (last != null && last.outgoing == m.outgoing && last.dhHead == w.dhHead)
        ? last
        : (RatchetEpoch(m.outgoing, w.dhHead, w.ratchetN)..lastN = w.ratchetN);
    if (!identical(e, last)) out.add(e);
    e
      ..messages += 1
      ..lastN = w.ratchetN > e.lastN ? w.ratchetN : e.lastN;
  }
  return out;
}
