/// QR scanning for identity verification: pixels → text → verdict.
library;

import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:helo/crypto/identity.dart';
import 'package:helo/verification/qr_image.dart';
import 'package:image/image.dart' as img;
import 'package:qr/qr.dart' as qr;
import 'package:zxing2/qrcode.dart' show Encoder, ErrorCorrectionLevel;

/// Render [text] as a QR code the way a screen would show it: black modules,
/// white quiet zone.
img.Image render(String text, {int scale = 6, int quiet = 4}) {
  final matrix = Encoder.encode(text, ErrorCorrectionLevel.m).matrix!;
  final int size = (matrix.width + 2 * quiet) * scale;
  final img.Image out = img.Image(width: size, height: size);
  img.fill(out, color: img.ColorRgb8(255, 255, 255));
  for (int x = 0; x < matrix.width; x++) {
    for (int y = 0; y < matrix.height; y++) {
      if (matrix.get(x, y) == 1) {
        img.fillRect(out,
            x1: (x + quiet) * scale,
            y1: (y + quiet) * scale,
            x2: (x + quiet + 1) * scale - 1,
            y2: (y + quiet + 1) * scale - 1,
            color: img.ColorRgb8(0, 0, 0));
      }
    }
  }
  return out;
}

void main() {
  late IdentityPublic alice;
  late IdentityPublic bob;
  late IdentityPublic mallory;

  setUpAll(() async {
    alice = (await IdentityKeyPair.generate()).public;
    bob = (await IdentityKeyPair.generate()).public;
    mallory = (await IdentityKeyPair.generate()).public;
  });

  test('a displayed code decodes from a PNG screenshot and verifies', () {
    final String shown = qrPayload(bob, alice);
    final String? read = decodeQrFromImageBytes(img.encodePng(render(shown)));
    expect(read, shown);
    expect(checkQrPayload(read!, me: alice, peer: bob), QrCheck.match);
  });

  test('a lossy, large camera-like JPEG still decodes', () {
    final String shown = qrPayload(bob, alice);
    // Put the code on a grey "desk" in a 2000 px photo, then JPEG it.
    final img.Image photo = img.Image(width: 2000, height: 1500);
    img.fill(photo, color: img.ColorRgb8(170, 170, 160));
    img.compositeImage(photo, render(shown, scale: 9), dstX: 600, dstY: 300);
    final Uint8List jpeg = img.encodeJpg(photo, quality: 55);
    expect(decodeQrFromImageBytes(jpeg), shown);
  }, timeout: const Timeout(Duration(seconds: 60))); // heavy decode; slow under a loaded full run

  test('a code for the wrong key decodes but does NOT verify', () {
    final String? read = decodeQrFromImageBytes(img.encodePng(render(qrPayload(mallory, alice))));
    expect(read, isNotNull);
    expect(checkQrPayload(read!, me: alice, peer: bob), QrCheck.peerKeyMismatch);
  });

  test('images without a code, and non-images, give null', () {
    final img.Image blank = img.Image(width: 300, height: 300);
    img.fill(blank, color: img.ColorRgb8(255, 255, 255));
    expect(decodeQrFromImageBytes(img.encodePng(blank)), isNull);
    final Random r = Random(7);
    expect(decodeQrFromImageBytes(Uint8List.fromList(List<int>.generate(5000, (_) => r.nextInt(256)))),
        isNull);
    expect(decodeQrFromImageBytes(Uint8List(0)), isNull);
  });

  test('an ordinary QR code (a URL) is read but is not a Helo code', () {
    final String? read = decodeQrFromImageBytes(img.encodePng(render('https://example.com/menu')));
    expect(read, 'https://example.com/menu');
    expect(checkQrPayload(read!, me: alice, peer: bob), QrCheck.notHelo);
  });

  test('the exact encoder the app displays with (qr_flutter / package:qr) decodes', () {
    // The app renders its code with QrImageView, at error-correction level L.
    final String shown = qrPayload(bob, alice);
    final qr.QrImage modules = qr.QrImage(
        qr.QrCode.fromData(data: shown, errorCorrectLevel: qr.QrErrorCorrectLevel.L));
    const int scale = 5;
    const int quiet = 4;
    final int size = (modules.moduleCount + 2 * quiet) * scale;
    final img.Image out = img.Image(width: size, height: size);
    img.fill(out, color: img.ColorRgb8(255, 255, 255));
    for (int row = 0; row < modules.moduleCount; row++) {
      for (int col = 0; col < modules.moduleCount; col++) {
        if (modules.isDark(row, col)) {
          img.fillRect(out,
              x1: (col + quiet) * scale,
              y1: (row + quiet) * scale,
              x2: (col + quiet + 1) * scale - 1,
              y2: (row + quiet + 1) * scale - 1,
              color: img.ColorRgb8(0, 0, 0));
        }
      }
    }
    expect(decodeQrFromImageBytes(img.encodePng(out)), shown);
  });
}
