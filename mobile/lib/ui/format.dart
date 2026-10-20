/// Small display formatters (no intl dependency needed for these).
library;

const List<String> _months = <String>[
  'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec',
];
const List<String> _weekdays = <String>['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

String two(int n) => n.toString().padLeft(2, '0');

String clock(DateTime t) => '${two(t.hour)}:${two(t.minute)}';

bool sameDay(DateTime a, DateTime b) =>
    a.year == b.year && a.month == b.month && a.day == b.day;

/// "14:05" today, "Yesterday", weekday within a week, else "12 Mar".
String listTime(DateTime t) {
  final DateTime now = DateTime.now();
  if (sameDay(t, now)) return clock(t);
  if (sameDay(t, now.subtract(const Duration(days: 1)))) return 'Yesterday';
  if (now.difference(t).inDays < 7) return _weekdays[t.weekday - 1];
  return '${t.day} ${_months[t.month - 1]}';
}

/// Date separator inside a conversation.
String dayLabel(DateTime t) {
  final DateTime now = DateTime.now();
  if (sameDay(t, now)) return 'Today';
  if (sameDay(t, now.subtract(const Duration(days: 1)))) return 'Yesterday';
  final String base = '${_weekdays[t.weekday - 1]}, ${t.day} ${_months[t.month - 1]}';
  return t.year == now.year ? base : '$base ${t.year}';
}

String lastSeen(DateTime t) {
  final Duration d = DateTime.now().difference(t);
  if (d.inMinutes < 1) return 'last seen just now';
  if (d.inMinutes < 60) return 'last seen ${d.inMinutes} min ago';
  if (sameDay(t, DateTime.now())) return 'last seen today at ${clock(t)}';
  return 'last seen ${listTime(t)} at ${clock(t)}';
}

String fileSize(int bytes) {
  if (bytes < 1024) return '$bytes B';
  if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
  return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
}

String timerLabel(int seconds) {
  if (seconds == 0) return 'Off';
  if (seconds % 86400 == 0) return '${seconds ~/ 86400} d';
  if (seconds % 3600 == 0) return '${seconds ~/ 3600} h';
  if (seconds % 60 == 0) return '${seconds ~/ 60} min';
  return '$seconds s';
}

const List<int> timerChoices = <int>[0, 30, 300, 3600, 86400, 604800];
