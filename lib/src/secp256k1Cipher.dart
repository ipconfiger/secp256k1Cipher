import "dart:typed_data";
import "dart:math";
import 'dart:convert' as convert;
import "package:pointycastle/pointycastle.dart";
import "package:pointycastle/export.dart";
import "package:pointycastle/api.dart";
import "package:pointycastle/ecc/api.dart";
import "package:pointycastle/ecc/curves/secp256k1.dart";
import "package:pointycastle/key_generators/api.dart";
import "package:pointycastle/key_generators/ec_key_generator.dart";
import "package:pointycastle/random/fortuna_random.dart";
import 'package:pointycastle/stream/salsa20.dart';

/// return a hex string version privateKey
String strinifyPrivateKey(ECPrivateKey privateKey){
  return privateKey.d.toRadixString(16);
}

/// return a hex string version publicKey
String strinifyPublicKey(ECPublicKey publicKey){
  var x_str = publicKey.Q.x.toBigInteger().toRadixString(16);
  var y_str = publicKey.Q.y.toBigInteger().toRadixString(16);
  return "${x_str}${y_str}";
}

/// return a privateKey from hex string
ECPrivateKey loadPrivateKey(String storedkey){
  var d = BigInt.parse(storedkey, radix:16);
  var param = ECCurve_secp256k1();
  return new ECPrivateKey(d, param);
}

/// return a publicKey from hex string
ECPublicKey loadPublicKey(String storedkey){
  var x = BigInt.parse(storedkey.substring(0, 64), radix: 16);
  var y = BigInt.parse(storedkey.substring(64), radix: 16);
  var param = ECCurve_secp256k1();
  var Q = param.curve.createPoint(x, y);
  return new ECPublicKey(Q, param);
}

/// return a ECPoint data secret
ECPoint rawSecret(String privateString, String publicString){
    var privateKey = loadPrivateKey(privateString);
    var publicKey = loadPublicKey(publicString);
    var secret = publicKey.Q * privateKey.d;
    return secret;
}

/// return a Bytes data secret 
Uint8List byteSecret(String privateString, String publicString){
    return rawSecret(privateString, publicString).getEncoded(true);
}

/// return Hex String secret
String getSecret(String privateString, String publicString){
    var secret = rawSecret(privateString, publicString);
    var x_str = secret.x.toBigInteger().toRadixString(16);
    var y_str = secret.y.toBigInteger().toRadixString(16);
    return "${x_str}${y_str}";   
}

/// Encrypt data using target public key
Map pubkeyEncrypt(String privateString, String publicString, String message){
  var secret = byteSecret(privateString, publicString);
  var key = Uint8List.fromList(secret.getRange(0, 32).toList());
  var iv = _seed(8);
  Salsa20Engine _cipher = Salsa20Engine();
  _cipher.reset();
  _cipher.init(true, _buildParams(key, Uint8List, iv));
  var enc_data = convert.base64.encode(_cipher.process(Uint8List.fromList(message.codeUnits)));
  return {
    'enc': enc_data,
    'iv': iv
  };
}

/// Decrypt data using self private key
String privateDecrypt(String privateString, String publicString, String b64encoded, Uint8List iv){
  var secret = byteSecret(privateString, publicString);
  var key = Uint8List.fromList(secret.getRange(0, 32).toList());
  Salsa20Engine _cipher = Salsa20Engine();
  _cipher.reset();
  _cipher.init(false, _buildParams(key, Uint8List, iv));
  Uint8List encd_data = convert.base64.decode(b64encoded);
  Uint8List raw_data = _cipher.process(encd_data);
  return new String.fromCharCodes(raw_data);
}


ParametersWithIV<KeyParameter> _buildParams(Uint8List key, Uint8List, iv) {
    return ParametersWithIV<KeyParameter>(KeyParameter(key), iv);
}

/// Generate Keypair
AsymmetricKeyPair<PublicKey, PrivateKey> generateKeyPair() {
  var keyParams = ECKeyGeneratorParameters(ECCurve_secp256k1());
  var random = FortunaRandom();
  random.seed(KeyParameter(_seed(32)));
  var generator = ECKeyGenerator();
  generator.init(ParametersWithRandom(keyParams, random));
  return generator.generateKeyPair();
}

Uint8List _seed(length) {
  var random = Random.secure();
  var seed = List<int>.generate(length, (_) => random.nextInt(256));
  return Uint8List.fromList(seed);
}