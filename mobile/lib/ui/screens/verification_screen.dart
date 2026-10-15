/// Safety-number verification.
///
/// This screen exists because cryptography authenticates KEYS, not PEOPLE. The
/// wording here deliberately avoids implying that scanning a QR code alone
/// proves identity: the code must be read from the other person's physical
/// device. Scanning a code someone sent you over the network proves nothing,
/// because an attacker who can substitute keys can also substitute a QR image.
library;

import 'package:flutter/material.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../../crypto/session.dart';
import '../../domain/session_manager.dart';
import '../theme.dart';
import '../widgets/verification_badge.dart';

class VerificationScreen extends StatefulWidget {
  const VerificationScreen({
    required this.manager,
    required this.peerDeviceId,
    super.key,
  });

  final SessionManager manager;
  final String peerDeviceId;

  @override
  State<VerificationScreen> createState() => _VerificationScreenState();
}

class _VerificationScreenState extends State<VerificationScreen> {
  String? _safetyNumber;
  String? _qr;
  String? _error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final String value =
          await widget.manager.safetyNumberFor(widget.peerDeviceId);
      final String qr =
          await widget.manager.verificationQrFor(widget.peerDeviceId);
      if (mounted) {
        setState(() {
          _safetyNumber = value;
          _qr = qr;
        });
      }
    } catch (_) {
      if (mounted) setState(() => _error = 'No session with this contact.');
    }
  }

  Future<void> _markVerified() async {
    try {
      await widget.manager.markVerified(widget.peerDeviceId);
      if (mounted) Navigator.pop(context);
    } catch (_) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text(
              'Cannot mark verified while an identity change is unresolved.',
            ),
          ),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final Conversation? c =
        widget.manager.conversations[widget.peerDeviceId];
    final String? number = _safetyNumber;
    final String? qr = _qr;

    return Scaffold(
      appBar: AppBar(title: const Text('Verify contact')),
      body: _error != null
          ? Center(child: Text(_error!))
          : number == null || qr == null
              ? const Center(child: CircularProgressIndicator())
              : SingleChildScrollView(
                  padding: const EdgeInsets.all(20),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: <Widget>[
                      if (c != null)
                        Center(
                            child: VerificationBadge(
                                status: c.session.verification)),
                      const SizedBox(height: 20),
                      Center(
                        child: Container(
                          padding: const EdgeInsets.all(12),
                          color: Colors.white,
                          child: QrImageView(
                            // Public identity encodings only, in the
                            // reference `qr_payload` format.
                            data: qr,
                            size: 190,
                            backgroundColor: Colors.white,
                          ),
                        ),
                      ),
                      const SizedBox(height: 22),
                      const Text('Safety number',
                          style: TextStyle(
                              fontSize: 12,
                              color: HeloColors.textSecondary,
                              letterSpacing: 1)),
                      const SizedBox(height: 10),
                      Container(
                        padding: const EdgeInsets.all(14),
                        decoration: BoxDecoration(
                          color: HeloColors.surface,
                          borderRadius: BorderRadius.circular(10),
                          border: Border.all(color: HeloColors.border),
                        ),
                        child: Text(
                          number,
                          textAlign: TextAlign.center,
                          style: const TextStyle(
                              fontSize: 15, letterSpacing: 1.5, height: 1.8),
                        ),
                      ),
                      const SizedBox(height: 20),
                      Container(
                        padding: const EdgeInsets.all(14),
                        decoration: BoxDecoration(
                          color: HeloColors.surface,
                          borderRadius: BorderRadius.circular(10),
                          border: Border.all(color: HeloColors.border),
                        ),
                        child: const Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: <Widget>[
                            Text('How to verify \u2014 and why it matters',
                                style: TextStyle(
                                    fontSize: 12,
                                    fontWeight: FontWeight.w700)),
                            SizedBox(height: 8),
                            Text(
                              'Compare this number with the one shown on your '
                              'contact\u2019s device. They must match exactly.\n\n'
                              'Do this in person, or over a channel you already '
                              'trust \u2014 a phone call where you recognise their '
                              'voice. Do NOT compare it over this app or any '
                              'other text channel: an attacker able to '
                              'substitute keys can also substitute the number '
                              'or the QR image you are sent.\n\n'
                              'Until you verify, encryption protects your '
                              'messages from the server and the network, but '
                              'nothing proves the person on the other end is '
                              'who you think it is.',
                              style: TextStyle(
                                  color: HeloColors.textSecondary,
                                  fontSize: 11.5,
                                  height: 1.55),
                            ),
                          ],
                        ),
                      ),
                      const SizedBox(height: 20),
                      if (c?.session.verification !=
                          VerificationStatus.verified)
                        FilledButton(
                          onPressed: _markVerified,
                          child: const Text('Numbers match \u2014 mark verified'),
                        ),
                    ],
                  ),
                ),
    );
  }
}
