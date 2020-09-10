import 'dart:typed_data';
import 'dart:html';

final crypto = window.crypto.subtle;

Future<Uint8List> sha256(Uint8List data) async =>
    crypto.digest()

Future<Uint8List> sha384(Uint8List data) async =>
    crypto.sha384.convert(data).bytes;
