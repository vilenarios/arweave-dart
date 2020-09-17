import 'dart:typed_data';

import 'package:arweave/src/crypto/driver/driver.dart';
import 'package:arweave/src/utils.dart';
import 'package:pointycastle/export.dart';

class Wallet {
  String get owner => encodeBigIntToBase64(publicKey.n);
  String get address => ownerToAddress(owner);

  RSAPublicKey publicKey;
  RSAPrivateKey privateKey;

  Wallet({this.publicKey, this.privateKey});

  Future<Uint8List> sign(Uint8List message) => signRsaPss(message, this);

  factory Wallet.fromJwk(Map<String, dynamic> jwk) {
    final modulus = decodeBase64ToBigInt(jwk['n']);

    return Wallet(
      publicKey: RSAPublicKey(
        modulus,
        decodeBase64ToBigInt(jwk['e']),
      ),
      privateKey: RSAPrivateKey(
        modulus,
        decodeBase64ToBigInt(jwk['d']),
        decodeBase64ToBigInt(jwk['p']),
        decodeBase64ToBigInt(jwk['q']),
      ),
    );
  }

  Map<String, dynamic> toJwk() => {
        'kty': 'RSA',
        'e': encodeBigIntToBase64(publicKey.e),
        'n': encodeBigIntToBase64(publicKey.n),
        'd': encodeBigIntToBase64(privateKey.d),
        'p': encodeBigIntToBase64(privateKey.p),
        'q': encodeBigIntToBase64(privateKey.q),
        'dp': encodeBigIntToBase64(
            privateKey.d % (privateKey.p - BigInt.from(1))),
        'dq': encodeBigIntToBase64(
            privateKey.d % (privateKey.q - BigInt.from(1))),
        'qi': encodeBigIntToBase64(privateKey.q.modInverse(privateKey.p)),
      };
}
