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
import 'package:hex/hex.dart';
import 'package:base58check/base58.dart';
import 'package:pointycastle/digests/ripemd160.dart';
import 'operator.dart';
import 'package:pointycastle/src/impl/secure_random_base.dart';
import "package:pointycastle/src/registry/registry.dart";
import "package:pointycastle/src/ufixnum.dart";

class NullSecureRandom extends SecureRandomBase {
  static final FactoryConfig FACTORY_CONFIG =
      new StaticFactoryConfig(SecureRandom, "Null", () => NullSecureRandom());

  var _nextValue = 0;

  String get algorithmName => "Null";

  void seed(CipherParameters params) {}

  int nextUint8() => clip8(_nextValue++);
}

/// return a hex string version privateKey
String strinifyPrivateKey(ECPrivateKey privateKey) {
  return privateKey.d.toRadixString(16);
}

String left_padding(String s, int width) {
  final padding_data = '000000000000000';
  final padding_width = width - s.length;
  if (padding_width < 1) {
    return s;
  }
  return "${padding_data.substring(0, padding_width)}${s}";
}

/// return a BTC Address
String btcAddress(ECPublicKey pubkey) {
  Digest sha256 = new Digest("SHA-256");
  Digest ripemd = new RIPEMD160Digest();
  final pub_bytes = pubkey.Q.getEncoded(false);
  final sha_hash = sha256.process(pub_bytes);
  final rip_hash = ripemd.process(sha_hash);
  // 生成验证
  final network_hash = [0x00] + rip_hash.toList();
  final check1 = sha256.process(Uint8List.fromList(network_hash));
  final check2 = sha256.process(check1);
  final final_check = check2.sublist(0, 4);
  final code_list = network_hash + final_check;
  Base58Encoder b58 = new Base58Encoder(
      '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz');
  return b58.convert(code_list);
}

const int _shaBytes = 256 ~/ 8;
final SHA3Digest sha3digest = SHA3Digest(_shaBytes * 8);

String ethAddress(ECPublicKey pubkey) {
  sha3digest.reset();
  final pub_bytes = pubkey.Q.getEncoded(false);
  final address_bytes = sha3digest.process(pub_bytes);
  final hex_string = HEX.encode(address_bytes);
  return '0x${hex_string.substring(24)}';
}

/// return a hex string version publicKey
String strinifyPublicKey(ECPublicKey publicKey) {
  Uint8List compressedKey = publicKey.Q.getEncoded(true);
  final code_list = compressedKey.toList();
  //print('raw codes:${code_list}');
  return code_list.map((w) {
    final hx = w.toRadixString(16);
    if (hx.length < 2) {
      return '0${hx}';
    }
    return hx;
  }).join('');
  //print('bytes:${raw_bytes}');
  //var x_str = left_padding(publicKey.Q.x.toBigInteger().toRadixString(16), 64);
  //var y_str = left_padding(publicKey.Q.y.toBigInteger().toRadixString(16), 64);
  //return "${x_str}${y_str}";
}

String privateSign(String strPrivateKey, String message) {
  ECPrivateKey privateKey = loadPrivateKey(strPrivateKey);
  ECDSASigner singer = new ECDSASigner(SHA512Digest(), new Mac('SHA-512/HMAC'));
  var privParams = new PrivateKeyParameter(
      new ECPrivateKey(privateKey.d, privateKey.parameters));
  var signParams =
      () => new ParametersWithRandom(privParams, new NullSecureRandom());
  singer.init(true, signParams());
  ECSignature signature = singer
      .generateSignature(Uint8List.fromList(convert.utf8.encode(message)));
  final x_s = signature.r.toRadixString(16);
  final y_s = signature.s.toRadixString(16);
  final hex_x = left_padding(x_s, 64);
  final hex_y = left_padding(y_s, 64);
  return hex_x + hex_y;
}

bool publicVerify(String strPublicKey, String message, String strSignature) {
  ECPublicKey publicKey = loadPublicKey(strPublicKey);
  ECDSASigner verifySinger =
      new ECDSASigner(SHA512Digest(), new Mac('SHA-512/HMAC'));
  var pubkeyParam = new PublicKeyParameter(
      new ECPublicKey(publicKey.Q, publicKey.parameters));

  final str_r = strSignature.substring(0, 64);
  final str_s = strSignature.substring(64, 128);
  final r = BigInt.parse(str_r, radix: 16);
  final s = BigInt.parse(str_s, radix: 16);

  ECSignature signature = new ECSignature(r, s);
  verifySinger.init(false, pubkeyParam);
  return verifySinger.verifySignature(
      Uint8List.fromList(convert.utf8.encode(message)), signature);
}

/// return a privateKey from hex string
ECPrivateKey loadPrivateKey(String storedkey) {
  final d = BigInt.parse(storedkey, radix: 16);
  final param = ECCurve_secp256k1();
  return new ECPrivateKey(d, param);
}

/// return a publicKey from hex string
ECPublicKey loadPublicKey(String storedkey) {
  final param = ECCurve_secp256k1();
  if (storedkey.length < 120) {
    var code_list = new List<int>();
    for (var _idx = 0; _idx < storedkey.length - 1; _idx += 2) {
      final hex_str = storedkey.substring(_idx, _idx + 2);
      code_list.add(int.parse(hex_str, radix: 16));
    }
    final Q = param.curve.decodePoint(code_list);
    return new ECPublicKey(Q, param);
  } else {
    final x = BigInt.parse(storedkey.substring(0, 64), radix: 16);
    final y = BigInt.parse(storedkey.substring(64), radix: 16);
    final Q = param.curve.createPoint(x, y);
    return new ECPublicKey(Q, param);
  }
}

/// return a ECPoint data secret
ECPoint rawSecret(String privateString, String publicString) {
  final privateKey = loadPrivateKey(privateString);
  final publicKey = loadPublicKey(publicString);
  final secret =
      scalar_multiple(privateKey.d, publicKey.Q); //publicKey.Q * privateKey.d;
  //final secret = publicKey.Q * privateKey.d;
  return secret;
}

/// return a Bytes data secret
List<List<int>> byteSecret(String privateString, String publicString) {
  final secret = rawSecret(privateString, publicString);
  final x_s = secret.x.toBigInteger().toRadixString(16);
  final y_s = secret.y.toBigInteger().toRadixString(16);
  final hex_x = left_padding(x_s, 64);
  final hex_y = left_padding(y_s, 64);
  final secret_bytes = Uint8List.fromList(HEX.decode('${hex_x}${hex_y}'));
  final pair = [
    secret_bytes.getRange(0, 32).toList(),
    secret_bytes.getRange(32, 40).toList()
  ];
  //print(secret_bytes);
  //print(pair);
  return pair;
}

/// Encrypt data using target public key
Map pubkeyEncrypt(String privateString, String publicString, String message) {
  convert.Utf8Encoder encoder = new convert.Utf8Encoder();
  final enced = pubkeyEncryptRaw(privateString, publicString,
      Uint8List.fromList(encoder.convert(message)));
  //print('enced:${enced["enc"]}');
  return {'enc': convert.base64.encode(enced['enc']), 'iv': enced['iv']};
}

Map pubkeyEncryptRaw(
    String privateString, String publicString, Uint8List data) {
  final secret_iv = byteSecret(privateString, publicString);
  final secret = Uint8List.fromList(secret_iv[0]);
  final iv = Uint8List.fromList(secret_iv[1]);
  //print('s:${secret} iv:${iv}');
  Salsa20Engine _cipher = Salsa20Engine();
  _cipher.reset();
  _cipher.init(true, _buildParams(secret, Uint8List, iv));
  final Uint8List enc_data = _cipher.process(data);
  return {'enc': enc_data, 'iv': convert.base64.encode(iv)};
}

/// Decrypt data using self private key
String privateDecrypt(
    String privateString, String publicString, String b64encoded,
    [String b64IV = ""]) {
  Uint8List encd_data = convert.base64.decode(b64encoded);
  final raw_data =
      privateDecryptRaw(privateString, publicString, encd_data, b64IV);
  convert.Utf8Decoder decode = new convert.Utf8Decoder();
  return decode.convert(raw_data.toList());
}

Uint8List privateDecryptRaw(
    String privateString, String publicString, Uint8List encd_data,
    [String b64IV = ""]) {
  final secret_iv = byteSecret(privateString, publicString);
  final secret = Uint8List.fromList(secret_iv[0]);
  final iv = b64IV.length > 6
      ? convert.base64.decode(b64IV)
      : Uint8List.fromList(secret_iv[1]);
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
      new ECPublicKey(Q, keyParams), new ECPrivateKey(d, keyParams));
}

Uint8List _seed(length) {
  var random = Random.secure();
  var seed = List<int>.generate(length, (_) => random.nextInt(256));
  return Uint8List.fromList(seed);
}
