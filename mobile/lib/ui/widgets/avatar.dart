import 'dart:typed_data';

import 'package:flutter/material.dart';

import '../theme.dart';

const List<Color> _tints = <Color>[
  Color(0xFF14B8A6), Color(0xFF6366F1), Color(0xFFF59E0B), Color(0xFFEC4899),
  Color(0xFF22C55E), Color(0xFF3B82F6), Color(0xFFA855F7), Color(0xFFEF4444),
];

Color tintFor(String seed) {
  int h = 0;
  for (final int c in seed.codeUnits) {
    h = (h * 31 + c) & 0x7fffffff;
  }
  return _tints[h % _tints.length];
}

/// Circular avatar: the picture if there is one, else initials on a colour
/// derived from the name, else a group icon.
class Avatar extends StatelessWidget {
  const Avatar({
    required this.label,
    this.image,
    this.size = 40,
    this.group = false,
    this.online = false,
    super.key,
  });

  final String label;
  final Uint8List? image;
  final double size;
  final bool group;
  final bool online;

  String get _initials {
    final List<String> parts =
        label.trim().split(RegExp(r'[\s._-]+')).where((String s) => s.isNotEmpty).toList();
    if (parts.isEmpty) return '?';
    if (parts.length == 1) return parts.first.substring(0, 1).toUpperCase();
    return (parts[0].substring(0, 1) + parts[1].substring(0, 1)).toUpperCase();
  }

  @override
  Widget build(BuildContext context) {
    final HeloPalette p = HeloPalette.of(context);
    final Color tint = tintFor(label);
    final Widget face = image != null
        ? ClipOval(
            child: Image.memory(image!, width: size, height: size, fit: BoxFit.cover,
                gaplessPlayback: true,
                errorBuilder: (BuildContext _, Object __, StackTrace? ___) =>
                    _fallback(tint)),
          )
        : _fallback(tint);
    if (!online) return SizedBox(width: size, height: size, child: face);
    return SizedBox(
      width: size,
      height: size,
      child: Stack(
        children: <Widget>[
          face,
          Positioned(
            right: 0,
            bottom: 0,
            child: Container(
              width: size * 0.28,
              height: size * 0.28,
              decoration: BoxDecoration(
                color: p.success,
                shape: BoxShape.circle,
                border: Border.all(color: p.surface, width: 2),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _fallback(Color tint) => Container(
        width: size,
        height: size,
        decoration: BoxDecoration(
          shape: BoxShape.circle,
          gradient: LinearGradient(
            colors: <Color>[tint.withValues(alpha: 0.95), tint.withValues(alpha: 0.65)],
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
          ),
        ),
        alignment: Alignment.center,
        child: group
            ? Icon(Icons.groups_rounded, color: Colors.white, size: size * 0.52)
            : Text(_initials,
                style: TextStyle(
                    color: Colors.white,
                    fontWeight: FontWeight.w700,
                    fontSize: size * 0.38)),
      );
}
