/// Shrinks a picked image for use as an avatar or group picture. Avatars
/// travel INLINE inside end-to-end encrypted profile/group messages, so they
/// must stay small (see `maxInlineImageBytes`).
library;

import 'dart:typed_data';
import 'dart:ui' as ui;

import '../protocol/payload.dart';

/// Returns PNG bytes no larger than [maxInlineImageBytes] with the aspect ratio
/// preserved, or null if the input could not be decoded as an image.
Future<Uint8List?> shrinkForAvatar(Uint8List bytes) async {
  final ui.ImageDescriptor descriptor;
  try {
    descriptor = await ui.ImageDescriptor.encoded(await ui.ImmutableBuffer.fromUint8List(bytes));
  } on Object {
    return null;
  }
  final bool wide = descriptor.width >= descriptor.height;
  for (final int dim in <int>[192, 160, 128, 96, 64]) {
    try {
      final ui.Codec codec = await descriptor.instantiateCodec(
        targetWidth: wide ? dim : null,
        targetHeight: wide ? null : dim,
      );
      final ui.FrameInfo frame = await codec.getNextFrame();
      final ByteData? data = await frame.image.toByteData(format: ui.ImageByteFormat.png);
      frame.image.dispose();
      if (data == null) return null;
      final Uint8List png = data.buffer.asUint8List();
      if (png.length <= maxInlineImageBytes) return png;
    } on Object {
      return null;
    }
  }
  return null;
}
