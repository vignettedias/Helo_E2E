/// Measured figures shown in the app, copied from the experiment outputs in
/// `research/results/*.json` (produced by `scripts/experiments/*.py`).
///
/// They are duplicated here because the app cannot read the repository at
/// runtime — so `test/research_numbers_test.dart` reads those JSON files and
/// fails if any constant here drifts from the measurement it claims to be.
/// Nothing in this file may be estimated, rounded for effect, or invented.
library;

/// E1 — padding: measured on the synthetic short-chat distribution
/// (log-normal, median 48 B). Values are (leakage bits per message, mean
/// overhead bytes) keyed by the policy name used in settings.
const Map<String, (double, double)> paddingE1 = <String, (double, double)>{
  'none': (7.636, 1.0),
  'block-160': (0.67, 107.33),
  'block-256': (0.326, 192.09),
  'pow2-256': (0.318, 194.54),
  'padme': (5.443, 3.76),
};

/// E2 — cost of the hybrid handshake, Python reference on one laptop.
/// Relative cost is the point; these are not mobile figures.
const double handshakeClassicalMedianMs = 0.49;
const double handshakeHybridMedianMs = 0.67;
const int firstEnvelopeClassicalBytes = 579;
const int firstEnvelopeHybridBytes = 2057;

/// E3 — what the relay's database holds, by column classification.
const int relayColumnsMetadata = 54;
const int relayColumnsCiphertext = 2;

/// E3 — distinct stored envelope sizes for the same six messages.
const int storedSizesUnpadded = 5;
const int storedSizesPadded = 3;
