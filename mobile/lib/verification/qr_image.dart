/// Reading a verification QR code out of an image (a camera frame, a photo or
/// a screenshot).
///
/// Decoding is pure Dart (`zxing2` + `image`): nothing is sent anywhere and no
/// decoder script is fetched at runtime. What the code SAYS is judged
/// separately by `checkQrPayload` — this file only turns pixels into text.
library;

import 'dart:typed_data';

import 'package:image/image.dart' as img;
import 'package:zxing2/qrcode.dart';

/// Larger photos are scaled down first: a QR code needs far fewer pixels than
/// a phone camera produces, and decoding cost grows with the pixel count.
const int maxDecodeSide = 1280;

/// Images bigger than this are refused outright (decoding a hostile image is
/// work, and a QR screenshot is never this large).
const int maxImageBytes = 15 * 1024 * 1024;

/// The text of the first QR code found in [encoded] (PNG, JPEG, GIF, BMP,
/// WebP…), or null if there is none or the image cannot be read.
String? decodeQrFromImageBytes(Uint8List encoded) {
  if (encoded.isEmpty || encoded.length > maxImageBytes) return null;
  final img.Image? decoded;
  try {
    decoded = img.decodeImage(encoded);
  } on Object {
    return null;
  }
  if (decoded == null) return null;
  return decodeQrFromImage(decoded);
}

/// As [decodeQrFromImageBytes], for an already-decoded image.
String? decodeQrFromImage(img.Image image) {
  img.Image work = image;
  final int longest = work.width > work.height ? work.width : work.height;
  if (longest > maxDecodeSide) {
    work = work.width >= work.height
        ? img.copyResize(work, width: maxDecodeSide)
        : img.copyResize(work, height: maxDecodeSide);
  }
  final Int32List pixels = work
      .convert(numChannels: 4)
      .getBytes(order: img.ChannelOrder.abgr)
      .buffer
      .asInt32List();
  final LuminanceSource source = RGBLuminanceSource(work.width, work.height, pixels);
  // HybridBinarizer copes with uneven light (camera photos); the global one
  // with small or flat images (screenshots). Try both before giving up.
  for (final Binarizer binarizer in <Binarizer>[HybridBinarizer(source), GlobalHistogramBinarizer(source)]) {
    try {
      return QRCodeReader().decode(BinaryBitmap(binarizer)).text;
    } on Object {
      // not found with this binarizer
    }
  }
  return null;
}
