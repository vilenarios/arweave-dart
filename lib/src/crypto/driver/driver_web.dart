import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/src/web_crypto/web_crypto.dart' as web_crypto;

import '../../models/models.dart';

Future<Uint8List> signRsaPss(Uint8List data, Wallet wallet) async {
  final jwk = wallet.toJwk();
  // Normalize fields of the JWK so the crypto package can parse it correctly.
  jwk.updateAll(
      (key, value) => key != 'kty' ? base64Url.normalize(value) : value);

  final signature = await web_crypto.rsaPssSign(
    data,
    KeyPair(
      privateKey: JwkPrivateKey.fromJson(jwk),
      publicKey: JwkPublicKey.fromJson(jwk),
    ),
    saltLength: 0,
    hashName: 'SHA-256',
  );

  return signature.bytes;
}
