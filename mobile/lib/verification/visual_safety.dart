/// A friendlier rendering of the safety number: 12 emoji instead of 60 digits.
///
/// Each 5-digit group (0..99999) picks one of 64 emoji, so the strip carries
/// 12 × 6 = 72 bits of the number — more than enough for two people comparing
/// in person to spot a substituted key, and far easier than reading digits
/// aloud. It is derived ONLY from the safety number, so both sides always see
/// the same strip. The digits and the QR scan remain the authoritative check.
library;

/// 64 visually distinct, commonly rendered emoji (no skin tones, no flags,
/// no look-alike pairs).
const List<String> safetyEmoji = <String>[
  '🐶', '🐱', '🦊', '🐻', '🐼', '🐨', '🐯', '🦁', '🐮', '🐷', '🐸', '🐵', '🐔', '🐧', '🦉', '🦋',
  '🐢', '🐙', '🦀', '🐬', '🐳', '🦈', '🐝', '🐞', '🌵', '🌲', '🍀', '🍄', '🌻', '🌹', '🌙', '⭐',
  '🔥', '🌈', '❄️', '⚡', '🍎', '🍋', '🍉', '🍇', '🍓', '🍒', '🥕', '🌽', '🍕', '🍩', '🎂', '☕',
  '⚽', '🏀', '🎸', '🎲', '🎯', '🚀', '🚲', '⛵', '🏠', '🔑', '🔔', '💡', '📚', '✏️', '🎁', '⏰',
];

/// The 12-emoji strip for a 60-digit safety number ("12345 67890 …").
/// Returns an empty list for anything that is not exactly 60 digits.
List<String> safetyEmojiStrip(String safetyNumber) {
  final String digits = safetyNumber.replaceAll(' ', '');
  if (digits.length != 60 || !RegExp(r'^\d{60}$').hasMatch(digits)) return const <String>[];
  return <String>[
    for (int i = 0; i < 60; i += 5) safetyEmoji[int.parse(digits.substring(i, i + 5)) % safetyEmoji.length],
  ];
}
