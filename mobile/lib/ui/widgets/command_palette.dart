/// Ctrl+K command palette: type to filter, Enter runs the top match.
library;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../theme.dart';

class DeckCommand {
  const DeckCommand(this.label, this.icon, this.action, {this.hint = '', this.danger = false});
  final String label;
  final IconData icon;
  final VoidCallback action;
  final String hint;
  final bool danger;
}

/// Case-insensitive match on every word of [query] against label + hint.
List<DeckCommand> filterCommands(List<DeckCommand> all, String query) {
  final List<String> words = query.toLowerCase().split(RegExp(r'\s+')).where((String w) => w.isNotEmpty).toList();
  if (words.isEmpty) return all;
  return all.where((DeckCommand c) {
    final String hay = '${c.label} ${c.hint}'.toLowerCase();
    return words.every(hay.contains);
  }).toList();
}

Future<void> showCommandPalette(BuildContext context, List<DeckCommand> commands) async {
  final DeckCommand? chosen = await showDialog<DeckCommand>(
    context: context,
    barrierColor: Colors.black54,
    builder: (BuildContext ctx) => _Palette(commands: commands),
  );
  chosen?.action();
}

class _Palette extends StatefulWidget {
  const _Palette({required this.commands});
  final List<DeckCommand> commands;

  @override
  State<_Palette> createState() => _PaletteState();
}

class _PaletteState extends State<_Palette> {
  final TextEditingController _q = TextEditingController();
  int _sel = 0;

  @override
  void dispose() {
    _q.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final HeloPalette p = HeloPalette.of(context);
    final List<DeckCommand> hits = filterCommands(widget.commands, _q.text);
    if (_sel >= hits.length) _sel = hits.isEmpty ? 0 : hits.length - 1;
    return Align(
      alignment: const Alignment(0, -0.6),
      child: Material(
        color: p.surface,
        shape: RoundedRectangleBorder(
            side: BorderSide(color: p.accent.withValues(alpha: 0.6)), borderRadius: BorderRadius.circular(4)),
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 560, maxHeight: 440),
          child: Column(mainAxisSize: MainAxisSize.min, children: <Widget>[
            CallbackShortcuts(
              bindings: <ShortcutActivator, VoidCallback>{
                const SingleActivator(LogicalKeyboardKey.arrowDown): () =>
                    setState(() => _sel = hits.isEmpty ? 0 : (_sel + 1) % hits.length),
                const SingleActivator(LogicalKeyboardKey.arrowUp): () =>
                    setState(() => _sel = hits.isEmpty ? 0 : (_sel - 1 + hits.length) % hits.length),
              },
              child: TextField(
                controller: _q,
                autofocus: true,
                onChanged: (_) => setState(() => _sel = 0),
                onSubmitted: (_) {
                  if (hits.isNotEmpty) Navigator.pop(context, hits[_sel]);
                },
                style: TextStyle(fontFamily: heloMono, color: p.accent),
                decoration: InputDecoration(
                  prefixText: '> ',
                  prefixStyle: TextStyle(fontFamily: heloMono, color: p.accent),
                  hintText: 'type a command or a chat…',
                  border: InputBorder.none,
                  enabledBorder: InputBorder.none,
                  focusedBorder: InputBorder.none,
                  filled: false,
                ),
              ),
            ),
            Divider(height: 1, color: p.border),
            Flexible(
              child: hits.isEmpty
                  ? Padding(
                      padding: const EdgeInsets.all(16),
                      child: Text('no match', style: TextStyle(color: p.textFaint)))
                  : ListView.builder(
                      shrinkWrap: true,
                      itemCount: hits.length,
                      itemBuilder: (BuildContext _, int i) {
                        final DeckCommand c = hits[i];
                        final Color fg = c.danger ? p.danger : p.textPrimary;
                        return ListTile(
                          dense: true,
                          selected: i == _sel,
                          selectedTileColor: p.accent.withValues(alpha: 0.12),
                          leading: Icon(c.icon, size: 18, color: c.danger ? p.danger : p.accent),
                          title: Text(c.label, style: TextStyle(color: fg, fontSize: 13)),
                          trailing: c.hint.isEmpty
                              ? null
                              : Text(c.hint, style: TextStyle(color: p.textFaint, fontSize: 11)),
                          onTap: () => Navigator.pop(context, c),
                        );
                      },
                    ),
            ),
            Padding(
              padding: const EdgeInsets.fromLTRB(12, 6, 12, 8),
              child: Text('↑↓ select · enter run · esc close',
                  style: TextStyle(color: p.textFaint, fontSize: 10.5)),
            ),
          ]),
        ),
      ),
    );
  }
}
