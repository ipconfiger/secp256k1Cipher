library secp256k1cipher.test.impl_test;
import 'package:secp256k1cipher/src/operator.dart';
import 'package:secp256k1cipher/src/secp256k1Cipher.dart';
import "package:test/test.dart";
import 'package:secp256k1cipher/secp256k1cipher.dart';
import "package:pointycastle/ecc/api.dart";


void main(){
  group('Keys', (){
    test('Generate Keys', (){
      final rs = BigInt.parse('31611240361787321350634878907371798843942705813719873982771920434159111865364');
      final v = inverse_mod(BigInt.from(1000), BigInt.parse('fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f', radix: 16));
      print(rs);
      print(v);
      expect(rs, equals(v));
    });
    test('Save and restore private key', (){
      int micro_seconds = 0;
      for (var _idx=0; _idx<100; _idx++){
        final t1 = new DateTime.now().millisecondsSinceEpoch;
        var keypare = generateKeyPair();
        micro_seconds += (new DateTime.now().millisecondsSinceEpoch - t1);
        var str_key = strinifyPrivateKey(keypare.privateKey);
        ECPrivateKey pk1 = keypare.privateKey;
        var pk2 = loadPrivateKey(str_key);
        var str_pub = strinifyPublicKey(keypare.publicKey);
        ECPublicKey pub1 = keypare.publicKey;
        final pub2 = loadPublicKey(str_pub);
        print("pub:\n${str_pub.length} \n pri:\n${str_key}");
        expect(pk1.d, equals(pk2.d));
        expect(pub1.Q, equals(pub2.Q));
      }
      print('avg: ${micro_seconds/100} ms');

    });
    test('Save and restore public key', () async{
      for (var _idx=0; _idx<100; _idx++){
        final alic_pubkey = '3d6b2142489ffa6d221da41e75e6c08a44a8d0e682b9fa6d768594d94da2adeeb85e248fa05dedcc4f95c32ab8707bb0ba579fd4b41bf28a0df5bfd7f731b809';
        final alic_prikey = '462c58255c68a0a1c1b5c89baa99688c81760169ed8c1502d53e50a820aed90a';
        final bob = generateKeyPair();
        print('success idx: ${_idx}');
        final s1 = rawSecret(alic_prikey, strinifyPublicKey(bob.publicKey));
        final s2 = rawSecret(strinifyPrivateKey(bob.privateKey), alic_pubkey);
        expect(s1, equals(s2));
      } 
    });
    test('Encrypt and Decrypt', (){
      int micro_seconds = 0;
      for(var i=0;i<100;i++){
        final alic_pubkey = '5cb38e0c76f2b28e112e78d96d46e79b04585f17c3bb81a11ad3ad327d9ccaf815b0d2c770fd31c7224671378d7129cdd3dba97ca1efd016e2a580048c6eec46';
        final alic_prikey = '9717f155a64b67e5aa22a9552824237119a373b84ffe62eb435cac6581099767';
        var bob = generateKeyPair();
        var raw_str = 'test test test';
        final t1 = new DateTime.now().millisecondsSinceEpoch;
        var enc_map = pubkeyEncrypt(alic_prikey, strinifyPublicKey(bob.publicKey), raw_str);
        micro_seconds += (new DateTime.now().millisecondsSinceEpoch - t1);
        var enc_str = enc_map['enc'];
        var iv = enc_map['iv'];
        var decryptd = privateDecrypt(strinifyPrivateKey(bob.privateKey), alic_pubkey, enc_str, iv);
        expect(raw_str, equals(decryptd));
      }
      print('avg: ${micro_seconds/100} ms');
      
    });
  });

}