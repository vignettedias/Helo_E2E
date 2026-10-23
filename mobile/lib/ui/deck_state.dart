/// App-wide Cyberdeck view modes, shared by the chat, the command palette and
/// the header toggles. View state only: nothing here is persisted or sent.
library;

import 'package:flutter/foundation.dart';

/// Crypto X-Ray: show what the relay stored under every message.
final ValueNotifier<bool> xrayMode = ValueNotifier<bool>(false);

/// Privacy blur: message contents stay blurred until hovered (shoulder-surfing
/// guard for demos and public screens; it does not stop screenshots).
final ValueNotifier<bool> privacyBlur = ValueNotifier<bool>(false);
