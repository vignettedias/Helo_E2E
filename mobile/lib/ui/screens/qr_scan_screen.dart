/// Scan a contact's verification QR code with the camera, or read it from an
/// image (a screenshot they sent in person, or a photo).
///
/// This screen only produces the code's TEXT (it pops with it). Judging it
/// against the keys this device holds is `Messenger.verifyByScannedCode`.
library;

import 'dart:async';

import 'package:camera/camera.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

import '../../crypto/identity.dart' show qrPrefix;
import '../../verification/qr_image.dart';
import '../theme.dart';

class QrScanScreen extends StatefulWidget {
  const QrScanScreen({required this.contactLabel, super.key});

  final String contactLabel;

  @override
  State<QrScanScreen> createState() => _QrScanScreenState();
}

class _QrScanScreenState extends State<QrScanScreen> {
  CameraController? _camera;
  String? _cameraProblem;
  String? _hint;
  bool _done = false;
  bool _picking = false;

  @override
  void initState() {
    super.initState();
    unawaited(_startCamera());
  }

  @override
  void dispose() {
    _done = true;
    unawaited(_camera?.dispose());
    super.dispose();
  }

  Future<void> _startCamera() async {
    try {
      final List<CameraDescription> cams = await availableCameras();
      if (cams.isEmpty) throw StateError('no camera');
      final CameraDescription cam = cams.firstWhere(
          (CameraDescription c) => c.lensDirection == CameraLensDirection.back,
          orElse: () => cams.first);
      final CameraController c = CameraController(cam, ResolutionPreset.medium, enableAudio: false);
      await c.initialize();
      if (!mounted) {
        await c.dispose();
        return;
      }
      setState(() => _camera = c);
      unawaited(_scanLoop(c));
    } on Object catch (e) {
      if (!mounted) return;
      setState(() => _cameraProblem = e is CameraException && e.code.contains('Denied')
          ? 'Camera permission was denied.'
          : 'No camera is available here.');
    }
  }

  /// Grab a still every ~0.6 s and look for a code. Stills rather than a frame
  /// stream, because the web camera supports only stills.
  Future<void> _scanLoop(CameraController c) async {
    while (!_done && mounted) {
      await Future<void>.delayed(const Duration(milliseconds: 600));
      if (_done || !mounted || _picking || !c.value.isInitialized || c.value.isTakingPicture) continue;
      try {
        final XFile shot = await c.takePicture();
        final Uint8List bytes = await shot.readAsBytes();
        final String? text = await compute(decodeQrFromImageBytes, bytes);
        if (text != null) _found(text);
      } on Object {
        // a missed frame; keep scanning
      }
    }
  }

  void _found(String text) {
    if (_done || !mounted) return;
    if (!text.startsWith(qrPrefix)) {
      setState(() => _hint = 'That QR code is not a HELO verification code.');
      return;
    }
    _done = true;
    Navigator.of(context).pop(text);
  }

  Future<void> _fromImage() async {
    setState(() => _picking = true);
    try {
      final FilePickerResult? picked = await FilePicker.pickFiles(type: FileType.image, withData: true);
      final Uint8List? bytes = picked?.files.single.bytes;
      if (bytes == null) return;
      final String? text = await compute(decodeQrFromImageBytes, bytes);
      if (text == null) {
        if (mounted) setState(() => _hint = 'No QR code was found in that image.');
        return;
      }
      _found(text);
    } finally {
      if (mounted) setState(() => _picking = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final HeloPalette p = HeloPalette.of(context);
    final CameraController? c = _camera;
    return Scaffold(
      appBar: AppBar(title: Text('Scan ${widget.contactLabel}\'s code')),
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 520),
          child: ListView(padding: const EdgeInsets.all(16), children: <Widget>[
            AspectRatio(
              aspectRatio: 1,
              child: ClipRRect(
                borderRadius: BorderRadius.circular(4),
                child: ColoredBox(
                  color: Colors.black,
                  child: c != null && c.value.isInitialized
                      ? FittedBox(
                          fit: BoxFit.cover,
                          child: SizedBox(
                            width: c.value.previewSize?.height ?? 480,
                            height: c.value.previewSize?.width ?? 480,
                            child: CameraPreview(c),
                          ),
                        )
                      : Center(
                          child: _cameraProblem == null
                              ? const CircularProgressIndicator()
                              : Padding(
                                  padding: const EdgeInsets.all(24),
                                  child: Text(_cameraProblem!,
                                      textAlign: TextAlign.center,
                                      style: const TextStyle(color: Colors.white70)),
                                ),
                        ),
                ),
              ),
            ),
            const SizedBox(height: 12),
            if (_hint != null)
              Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: Text(_hint!, textAlign: TextAlign.center, style: TextStyle(color: p.warning)),
              ),
            Text(
              'Ask ${widget.contactLabel} to open your chat → Details & security → Compare, and hold the '
              'code in front of the camera. You can also choose a screenshot or photo of their code.',
              textAlign: TextAlign.center,
              style: TextStyle(color: p.textSecondary, fontSize: 12.5),
            ),
            const SizedBox(height: 12),
            OutlinedButton.icon(
              onPressed: _picking ? null : _fromImage,
              icon: const Icon(Icons.image_outlined),
              label: const Text('Choose an image'),
            ),
            const SizedBox(height: 8),
            Text(
              'The code is checked on this device against the keys you already hold. It is never '
              'uploaded, and scanning never adds or replaces a key.',
              textAlign: TextAlign.center,
              style: TextStyle(color: p.textFaint, fontSize: 11.5),
            ),
          ]),
        ),
      ),
    );
  }
}
