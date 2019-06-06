library secp256k1Cipher.test.impl_test;

import 'package:secp256k1Cipher/src/secp256k1Cipher.dart';
import "package:test/test.dart";
import 'package:secp256k1Cipher/cipher.dart';
import "package:pointycastle/ecc/api.dart";


void main(){
  group('Keys', (){
    test('Generate Keys', (){
      var keypare = generateKeyPair();
      expect(true, equals(true));
    });
    test('Save and restore private key', (){
      var keypare = generateKeyPair();
      var str_key = strinifyPrivateKey(keypare.privateKey);
      ECPrivateKey pk1 = keypare.privateKey;
      var pk2 = loadPrivateKey(str_key);
      expect(pk1.d, equals(pk2.d));
    });
    test('Save and restore public key', (){
      var keypare = generateKeyPair();
      var str_key = strinifyPublicKey(keypare.publicKey);
      ECPublicKey pk1 = keypare.publicKey;
      var pk2 = loadPublicKey(str_key);
      expect(pk1.Q, equals(pk2.Q));
    });
    test('Encrypt and Decrypt', (){
      var alic = generateKeyPair();
      var bob = generateKeyPair();
      var raw_str = 'Encrypt and decrypt data use secp256k1';
      var enc_map = pubkeyEncrypt(strinifyPrivateKey(alic.privateKey), strinifyPublicKey(bob.publicKey), raw_str);
      var enc_str = enc_map['enc'];
      var iv = enc_map['iv'];
      var decryptd = privateDecrypt(strinifyPrivateKey(bob.privateKey), strinifyPublicKey(alic.publicKey), enc_str, iv);
      expect(raw_str, equals(decryptd));
    });
  });

}