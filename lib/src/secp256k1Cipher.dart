import "dart:typed_data";
import "dart:math";
import 'dart:convert' as convert;
import "package:pointycastle/pointycastle.dart";
import "package:pointycastle/export.dart";
import "package:pointycastle/api.dart";
import "package:pointycastle/ecc/api.dart";
import "package:pointycastle/ecc/curves/secp256k1.dart";
import "package:pointycastle/random/fortuna_random.dart";
import 'package:pointycastle/stream/salsa20.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'operator.dart';

/// return a hex string version privateKey
String strinifyPrivateKey(ECPrivateKey privateKey){
  return privateKey.d.toRadixString(16);
}

String left_padding(String s, int width){
  final padding_data = '000000000000000';
  final padding_width = width - s.length;
  if (padding_width < 1){
    return s;
  }
  return "${padding_data.substring(0, padding_width)}${s}";
}


/// return a hex string version publicKey
String strinifyPublicKey(ECPublicKey publicKey){
  var x_str = left_padding(publicKey.Q.x.toBigInteger().toRadixString(16), 64);
  var y_str = left_padding(publicKey.Q.y.toBigInteger().toRadixString(16), 64);
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
    final privateKey = loadPrivateKey(privateString);
    final publicKey = loadPublicKey(publicString);
    final secret = scalar_multiple(privateKey.d, publicKey.Q); //publicKey.Q * privateKey.d;
    //final secret = publicKey.Q * privateKey.d;
    return secret;
}

/// return a Bytes data secret 
Uint8List byteSecret(String privateString, String publicString){
    final secret = rawSecret(privateString, publicString);
    final x_s = secret.x.toBigInteger().toRadixString(16);
    final y_s = secret.x.toBigInteger().toRadixString(16);
    final secret_hex = '${x_s}${y_s}';
    return SHA256Digest().process(Uint8List.fromList(secret_hex.codeUnits));
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
  final enced = pubkeyEncryptRaw(privateString, publicString, Uint8List.fromList(message.codeUnits));
  return {
    'enc': convert.base64.encode(enced['enc']),
    'iv':enced['iv']
  };
}

Map pubkeyEncryptRaw(String privateString, String publicString, Uint8List data){
  final secret = byteSecret(privateString, publicString);
  final iv = _seed(8);
  Salsa20Engine _cipher = Salsa20Engine();
  _cipher.reset();
  _cipher.init(true, _buildParams(secret, Uint8List, iv));
  final Uint8List enc_data = _cipher.process(data);
  return {
    'enc': enc_data,
    'iv': convert.base64.encode(iv)
  };
}


/// Decrypt data using self private key
String privateDecrypt(String privateString, String publicString, String b64encoded, String b64IV){
  Uint8List encd_data = convert.base64.decode(b64encoded);
  final raw_data = privateDecryptRaw(privateString, publicString, encd_data, b64IV);
  return new String.fromCharCodes(raw_data);
}

Uint8List privateDecryptRaw(String privateString, String publicString, Uint8List encd_data, String b64IV){
  var secret = byteSecret(privateString, publicString);
  Uint8List iv = convert.base64.decode(b64IV);
  Salsa20Engine _cipher = Salsa20Engine();
  _cipher.reset();
  _cipher.init(false, _buildParams(secret, Uint8List, iv));
  return _cipher.process(encd_data);
}


ParametersWithIV<KeyParameter> _buildParams(Uint8List key, Uint8List, iv) {
    return ParametersWithIV<KeyParameter>(KeyParameter(key), iv);
}

/// Generate Keypair
AsymmetricKeyPair<PublicKey, PrivateKey> generateKeyPair() {
  var keyParams = ECCurve_secp256k1();
  var random = FortunaRandom();
  random.seed(KeyParameter(_seed(32)));
  var n = keyParams.n;
  var nBitLength = n.bitLength;
  var d;
  do {
    d = random.nextBigInteger(nBitLength);
  } while (d == BigInt.zero || (d >= n));
  ECPoint Q = scalar_multiple(d, keyParams.G);
  return new AsymmetricKeyPair(
        new ECPublicKey(Q, keyParams),
        new ECPrivateKey(d, keyParams));
}

Uint8List _seed(length) {
  var random = Random.secure();
  var seed = List<int>.generate(length, (_) => random.nextInt(256));
  return Uint8List.fromList(seed);
}