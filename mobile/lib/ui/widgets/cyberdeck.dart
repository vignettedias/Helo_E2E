/// Cyberdeck chrome: the terminal title with a blinking cursor, and the CRT
/// scanline overlay. Decoration only — nothing here carries security state.
library;

import 'package:flutter/material.dart';

import '../theme.dart';

/// `HELO:~$ █` — the cursor blinks unless the platform asks for reduced motion.
class TerminalTitle extends StatefulWidget {
  const TerminalTitle({this.size = 18, super.key});

  final double size;

  @override
  State<TerminalTitle> createState() => _TerminalTitleState();
}

class _TerminalTitleState extends State<TerminalTitle> with SingleTickerProviderStateMixin {
  late final AnimationController _blink =
      AnimationController(vsync: this, duration: const Duration(milliseconds: 1100));

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (MediaQuery.disableAnimationsOf(context)) {
      _blink.stop();
      _blink.value = 1;
    } else if (!_blink.isAnimating) {
      _blink.repeat();
    }
  }

  @override
  void dispose() {
    _blink.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final HeloPalette p = HeloPalette.of(context);
    final TextStyle base = TextStyle(fontSize: widget.size, fontWeight: FontWeight.w700, letterSpacing: 1);
    return Semantics(
      label: 'HELO',
      excludeSemantics: true,
      child: Row(mainAxisSize: MainAxisSize.min, children: <Widget>[
        Text('HELO', style: base.copyWith(color: p.accent, shadows: _glow(p.accent))),
        Text(':~\$ ', style: base.copyWith(color: p.textFaint)),
        AnimatedBuilder(
          animation: _blink,
          builder: (BuildContext _, Widget? __) => Opacity(
            opacity: _blink.value < 0.55 ? 1 : 0,
            child: Container(width: widget.size * 0.55, height: widget.size * 1.05, color: p.accent),
          ),
        ),
      ]),
    );
  }
}

/// A soft phosphor glow for accent text (dark theme only; no-op in light).
List<Shadow> _glow(Color c) => <Shadow>[Shadow(color: c.withValues(alpha: 0.55), blurRadius: 10)];

/// Faint horizontal scanlines over the whole app in the dark theme.
/// Ignores pointer events, so it never intercepts a tap.
class Scanlines extends StatelessWidget {
  const Scanlines({required this.child, super.key});

  final Widget child;

  @override
  Widget build(BuildContext context) {
    if (Theme.of(context).brightness != Brightness.dark) return child;
    return Stack(children: <Widget>[
      child,
      const Positioned.fill(child: IgnorePointer(child: RepaintBoundary(child: CustomPaint(painter: _ScanPainter())))),
    ]);
  }
}

class _ScanPainter extends CustomPainter {
  const _ScanPainter();

  @override
  void paint(Canvas canvas, Size size) {
    final Paint line = Paint()..color = const Color(0x0DFFFFFF);
    for (double y = 0; y < size.height; y += 3) {
      canvas.drawRect(Rect.fromLTWH(0, y, size.width, 1), line);
    }
  }

  @override
  bool shouldRepaint(covariant _ScanPainter oldDelegate) => false;
}
