/// Visual system: "Cyberdeck" -- a phosphor-green terminal on near-black
/// (dark) and a printed-terminal-paper variant (light), monospace throughout.
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

  /// Phosphor terminal: green signal, cyan info, magenta alarm.
  static const HeloPalette dark = HeloPalette(
    backdrop: Color(0xFF020403),
    background: Color(0xFF050807),
    surface: Color(0xFF0A100D),
    surfaceRaised: Color(0xFF101A15),
    border: Color(0xFF1C3328),
    accent: Color(0xFF39FF88),
    onAccent: Color(0xFF001A0B),
    textPrimary: Color(0xFFCFFFE2),
    textSecondary: Color(0xFF7FB89A),
    textFaint: Color(0xFF4E7A63),
    bubbleOut: Color(0xFF0B2A1A),
    bubbleIn: Color(0xFF0E1822),
    success: Color(0xFF39FF88),
    warning: Color(0xFFFFC94D),
    danger: Color(0xFFFF2E88),
    info: Color(0xFF22D3EE),
  );

  /// Daylight: green-bar printer paper.
  static const HeloPalette light = HeloPalette(
    backdrop: Color(0xFFDCE7DF),
    background: Color(0xFFEFF5F0),
    surface: Color(0xFFFAFDF9),
    surfaceRaised: Color(0xFFE3EEE6),
    border: Color(0xFFB9CEBF),
    accent: Color(0xFF00803A),
    onAccent: Color(0xFFFFFFFF),
    textPrimary: Color(0xFF0B1F14),
    textSecondary: Color(0xFF355A44),
    textFaint: Color(0xFF6F8C7A),
    bubbleOut: Color(0xFFD3EBDB),
    bubbleIn: Color(0xFFFFFFFF),
    success: Color(0xFF00803A),
    warning: Color(0xFFA15C00),
    danger: Color(0xFFC2185B),
    info: Color(0xFF0E7490),
  );

  static HeloPalette of(BuildContext context) =>
      Theme.of(context).extension<HeloPalette>() ?? dark;

  @override
  HeloPalette copyWith() => this;

  @override
  HeloPalette lerp(ThemeExtension<HeloPalette>? other, double t) =>
      t < 0.5 || other is! HeloPalette ? this : other;
}

/// The bundled terminal typeface (assets/fonts, SIL OFL 1.1).
const String heloMono = 'JetBrainsMono';

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
    borderRadius: BorderRadius.circular(4),
    borderSide: BorderSide(color: p.border),
  );

  return ThemeData(
    fontFamily: heloMono,
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
        borderRadius: BorderRadius.circular(4),
        side: BorderSide(color: p.border),
      ),
    ),
    dialogTheme: DialogThemeData(
      backgroundColor: p.surface,
      surfaceTintColor: Colors.transparent,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(6)),
    ),
    bottomSheetTheme: BottomSheetThemeData(
      backgroundColor: p.surface,
      surfaceTintColor: Colors.transparent,
      showDragHandle: true,
    ),
    popupMenuTheme: PopupMenuThemeData(
      color: p.surfaceRaised,
      surfaceTintColor: Colors.transparent,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(4)),
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
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(4)),
        textStyle: const TextStyle(fontFamily: heloMono, fontWeight: FontWeight.w700),
      ),
    ),
    outlinedButtonTheme: OutlinedButtonThemeData(
      style: OutlinedButton.styleFrom(
        foregroundColor: p.textPrimary,
        side: BorderSide(color: p.border),
        padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 13),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(4)),
      ),
    ),
    listTileTheme: ListTileThemeData(
      iconColor: p.textSecondary,
      textColor: p.textPrimary,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(4)),
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
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(4)),
    ),
    snackBarTheme: SnackBarThemeData(
      behavior: SnackBarBehavior.floating,
      backgroundColor: p.surfaceRaised,
      contentTextStyle: TextStyle(color: p.textPrimary),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(4)),
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
