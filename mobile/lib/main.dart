import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'app.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  // On the web, right-click must reach the app (message actions menu)
  // instead of opening the browser's own context menu.
  if (kIsWeb) await BrowserContextMenu.disableContextMenu();
  runApp(const HeloApp());
}
