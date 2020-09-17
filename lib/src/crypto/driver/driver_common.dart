import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import '../../models/models.dart';

Future<Uint8List> signRsaPss(Uint8List data, Wallet wallet) async {
  var signer = PSSSigner(RSAEngine(), SHA256Digest(), SHA256Digest())
    ..init(
      true,
      ParametersWithSalt(
        PrivateKeyParameter<RSAPrivateKey>(wallet.privateKey),
        null,
      ),
    );

  final signature = await signer.generateSignature(data);
  return signature.bytes;
}
