/// A minimal async mutex.
///
/// Every operation that reads or advances ratchet state runs under one lock.
/// Without it, a receive and a send can interleave on the same session:
/// `decryptMessage` commits a COPY of the ratchet taken before an interleaved
/// `encryptMessage` advanced it, rolling the sending chain back — and the next
/// message would reuse a message key and its derived AES-GCM nonce.
library;

import 'dart:async';

class AsyncLock {
  Future<void> _tail = Future<void>.value();

  /// Run [action] after every previously scheduled action has finished.
  Future<T> run<T>(Future<T> Function() action) {
    final Future<void> previous = _tail;
    final Completer<void> done = Completer<void>();
    _tail = done.future;
    return previous.then((_) => action()).whenComplete(done.complete);
  }
}
