/// Visual system: deep navy (dark) and clean light themes with one teal
/// accent.
///
/// One rule governs the security states: they are never conveyed by colour
/// alone. Every verification or downgrade state carries an icon and a word
/// as well, because "verified" versus "key changed" is exactly the
/// distinction an attacker benefits from blurring.
library;

import 'package:flutter/material.dart';

@immutable
class HeloPalette extends ThemeExtension<HeloPalette> {
  const HeloPalette({
    required this.backdrop,
    required this.background,
    required this.surface,
    required this.surfaceRaised,
    required this.border,
    required this.accent,
    required this.onAccent,
    required this.textPrimary,
    required this.textSecondary,
    required this.textFaint,
    required this.bubbleOut,
    required this.bubbleIn,
    required this.success,
    required this.warning,
    required this.danger,
    required this.info,
  });

  final Color backdrop;
  final Color background;
  final Color surface;
  final Color surfaceRaised;
  final Color border;
  final Color accent;
  final Color onAccent;
  final Color textPrimary;
  final Color textSecondary;
  final Color textFaint;
  final Color bubbleOut;
  final Color bubbleIn;
  final Color success;
  final Color warning;
  final Color danger;
  final Color info;

  static const HeloPalette dark = HeloPalette(
    backdrop: Color(0xFF070B16),
    background: Color(0xFF0B1020),
    surface: Color(0xFF111A2B),
    surfaceRaised: Color(0xFF18233A),
    border: Color(0xFF233049),
    accent: Color(0xFF2DD4BF),
    onAccent: Color(0xFF042F2B),
    textPrimary: Color(0xFFE6EDF7),
    textSecondary: Color(0xFF9AA8BD),
    textFaint: Color(0xFF66748A),
    bubbleOut: Color(0xFF0E3B3A),
    bubbleIn: Color(0xFF18233A),
    success: Color(0xFF34D399),
    warning: Color(0xFFFBBF24),
    danger: Color(0xFFF87171),
    info: Color(0xFF60A5FA),
  );

  static const HeloPalette light = HeloPalette(
    backdrop: Color(0xFFE6EBF3),
    background: Color(0xFFF4F7FB),
    surface: Color(0xFFFFFFFF),
    surfaceRaised: Color(0xFFEEF2F8),
    border: Color(0xFFDCE3EE),
    accent: Color(0xFF0F8F80),
    onAccent: Color(0xFFFFFFFF),
    textPrimary: Color(0xFF0F172A),
    textSecondary: Color(0xFF475569),
    textFaint: Color(0xFF8592A6),
    bubbleOut: Color(0xFFD6F2EC),
    bubbleIn: Color(0xFFFFFFFF),
    success: Color(0xFF047857),
    warning: Color(0xFFB45309),
    danger: Color(0xFFDC2626),
    info: Color(0xFF2563EB),
  );

  static HeloPalette of(BuildContext context) =>
      Theme.of(context).extension<HeloPalette>() ?? dark;

  @override
  HeloPalette copyWith() => this;

  @override
  HeloPalette lerp(ThemeExtension<HeloPalette>? other, double t) =>
      t < 0.5 || other is! HeloPalette ? this : other;
}

ThemeData buildTheme(Brightness brightness) {
  final HeloPalette p = brightness == Brightness.dark ? HeloPalette.dark : HeloPalette.light;
  final ColorScheme scheme = ColorScheme.fromSeed(
    seedColor: p.accent,
    brightness: brightness,
  ).copyWith(
    primary: p.accent,
    onPrimary: p.onAccent,
    surface: p.surface,
    onSurface: p.textPrimary,
    error: p.danger,
    outline: p.border,
    outlineVariant: p.border,
  );
  final OutlineInputBorder field = OutlineInputBorder(
    borderRadius: BorderRadius.circular(12),
    borderSide: BorderSide(color: p.border),
  );

  return ThemeData(
    useMaterial3: true,
    brightness: brightness,
    colorScheme: scheme,
    extensions: <ThemeExtension<dynamic>>[p],
    scaffoldBackgroundColor: p.background,
    canvasColor: p.background,
    dividerColor: p.border,
    splashFactory: InkSparkle.splashFactory,
    appBarTheme: AppBarTheme(
      backgroundColor: p.surface,
      foregroundColor: p.textPrimary,
      surfaceTintColor: Colors.transparent,
      elevation: 0,
      scrolledUnderElevation: 0,
      titleTextStyle: TextStyle(
          color: p.textPrimary, fontSize: 17, fontWeight: FontWeight.w600),
    ),
    cardTheme: CardThemeData(
      color: p.surface,
      elevation: 0,
      margin: EdgeInsets.zero,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(14),
        side: BorderSide(color: p.border),
      ),
    ),
    dialogTheme: DialogThemeData(
      backgroundColor: p.surface,
      surfaceTintColor: Colors.transparent,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(18)),
    ),
    bottomSheetTheme: BottomSheetThemeData(
      backgroundColor: p.surface,
      surfaceTintColor: Colors.transparent,
      showDragHandle: true,
    ),
    popupMenuTheme: PopupMenuThemeData(
      color: p.surfaceRaised,
      surfaceTintColor: Colors.transparent,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: p.surfaceRaised,
      isDense: true,
      contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 13),
      border: field,
      enabledBorder: field,
      focusedBorder: field.copyWith(borderSide: BorderSide(color: p.accent, width: 1.4)),
      errorBorder: field.copyWith(borderSide: BorderSide(color: p.danger)),
      hintStyle: TextStyle(color: p.textFaint),
      labelStyle: TextStyle(color: p.textSecondary),
    ),
    filledButtonTheme: FilledButtonThemeData(
      style: FilledButton.styleFrom(
        backgroundColor: p.accent,
        foregroundColor: p.onAccent,
        padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 14),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        textStyle: const TextStyle(fontWeight: FontWeight.w600),
      ),
    ),
    outlinedButtonTheme: OutlinedButtonThemeData(
      style: OutlinedButton.styleFrom(
        foregroundColor: p.textPrimary,
        side: BorderSide(color: p.border),
        padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 13),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      ),
    ),
    listTileTheme: ListTileThemeData(
      iconColor: p.textSecondary,
      textColor: p.textPrimary,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
    ),
    switchTheme: SwitchThemeData(
      thumbColor: WidgetStateProperty.resolveWith((Set<WidgetState> s) =>
          s.contains(WidgetState.selected) ? p.onAccent : p.textSecondary),
      trackColor: WidgetStateProperty.resolveWith((Set<WidgetState> s) =>
          s.contains(WidgetState.selected) ? p.accent : p.surfaceRaised),
    ),
    chipTheme: ChipThemeData(
      backgroundColor: p.surfaceRaised,
      selectedColor: p.accent.withValues(alpha: 0.18),
      side: BorderSide(color: p.border),
      labelStyle: TextStyle(color: p.textPrimary, fontSize: 12.5),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
    ),
    snackBarTheme: SnackBarThemeData(
      behavior: SnackBarBehavior.floating,
      backgroundColor: p.surfaceRaised,
      contentTextStyle: TextStyle(color: p.textPrimary),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
    ),
    tooltipTheme: TooltipThemeData(
      decoration: BoxDecoration(color: p.surfaceRaised, borderRadius: BorderRadius.circular(8)),
      textStyle: TextStyle(color: p.textPrimary, fontSize: 12),
    ),
    textTheme: TextTheme(
      bodyMedium: TextStyle(color: p.textPrimary, height: 1.4, fontSize: 14),
      bodySmall: TextStyle(color: p.textSecondary, fontSize: 12.5),
      labelSmall: TextStyle(color: p.textFaint, fontSize: 11),
      titleMedium: TextStyle(color: p.textPrimary, fontWeight: FontWeight.w600),
    ),
  );
}
