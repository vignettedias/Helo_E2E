/// Visual system: dark, restrained, security-forward.
///
/// One rule governs everything here: security state must be legible without
/// relying on colour alone. Every verification state carries an icon and a
/// text label as well as a colour, because a colour-blind user must be able to
/// tell "verified" from "identity changed" — and that is precisely the
/// distinction an attacker benefits from blurring.
library;

import 'package:flutter/material.dart';

abstract final class HeloColors {
  static const Color backdrop = Color(0xFF060809); // outside the app column
  static const Color background = Color(0xFF0A0D10);
  static const Color surface = Color(0xFF12171C);
  static const Color surfaceRaised = Color(0xFF1A2128);
  static const Color border = Color(0xFF243039);

  static const Color accent = Color(0xFF35E0A1); // verified / secure
  static const Color accentDim = Color(0xFF1F8F68);
  static const Color warning = Color(0xFFFFB454); // unverified
  static const Color danger = Color(0xFFFF5C5C); // identity changed

  static const Color textPrimary = Color(0xFFE6EDF3);
  static const Color textSecondary = Color(0xFF8B98A5);
  static const Color textFaint = Color(0xFF5A6672);

  static const Color bubbleOut = Color(0xFF1B3A2F);
  static const Color bubbleIn = Color(0xFF1A2128);
}

ThemeData heloTheme() {
  const ColorScheme scheme = ColorScheme.dark(
    primary: HeloColors.accent,
    onPrimary: Color(0xFF04120C),
    secondary: HeloColors.accentDim,
    surface: HeloColors.surface,
    onSurface: HeloColors.textPrimary,
    error: HeloColors.danger,
  );

  return ThemeData(
    useMaterial3: true,
    colorScheme: scheme,
    scaffoldBackgroundColor: HeloColors.background,
    fontFamily: 'monospace',
    appBarTheme: const AppBarTheme(
      backgroundColor: HeloColors.background,
      surfaceTintColor: Colors.transparent,
      elevation: 0,
      centerTitle: false,
      titleTextStyle: TextStyle(
        color: HeloColors.textPrimary,
        fontSize: 18,
        fontWeight: FontWeight.w600,
        letterSpacing: 0.2,
      ),
    ),
    cardTheme: CardThemeData(
      color: HeloColors.surface,
      elevation: 0,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: const BorderSide(color: HeloColors.border),
      ),
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: HeloColors.surface,
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(10),
        borderSide: const BorderSide(color: HeloColors.border),
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(10),
        borderSide: const BorderSide(color: HeloColors.border),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(10),
        borderSide: const BorderSide(color: HeloColors.accentDim),
      ),
      hintStyle: const TextStyle(color: HeloColors.textFaint),
    ),
    filledButtonTheme: FilledButtonThemeData(
      style: FilledButton.styleFrom(
        backgroundColor: HeloColors.accent,
        foregroundColor: const Color(0xFF04120C),
        padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 14),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(10),
        ),
      ),
    ),
    dividerTheme: const DividerThemeData(color: HeloColors.border, space: 1),
    textTheme: const TextTheme(
      bodyMedium: TextStyle(color: HeloColors.textPrimary, height: 1.45),
      bodySmall: TextStyle(color: HeloColors.textSecondary, fontSize: 12),
      labelSmall: TextStyle(color: HeloColors.textFaint, fontSize: 11),
    ),
  );
}
