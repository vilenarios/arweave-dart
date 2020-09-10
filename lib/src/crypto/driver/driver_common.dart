import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

Future<Uint8List> sha256(Uint8List data) async =>
    crypto.sha256.convert(data).bytes;

Future<Uint8List> sha384(Uint8List data) async =>
    crypto.sha384.convert(data).bytes;
