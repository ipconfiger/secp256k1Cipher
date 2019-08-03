library secp256k1cipher.test.impl_test;
import 'dart:convert' as convert;
import 'dart:io';
import 'dart:typed_data';
import 'package:secp256k1cipher/src/operator.dart';
import 'package:secp256k1cipher/src/secp256k1Cipher.dart';
import "package:test/test.dart";
import 'package:secp256k1cipher/secp256k1cipher.dart';
import "package:pointycastle/ecc/api.dart";


void main(){
  group('Keys', (){
    test('Generate Keys', (){
      File f = new File('/Users/alex/study/test.csv');
      final lines = [];
      for (var _idx=0; _idx < 100; _idx++){
        final keypare = generateKeyPair();
        final ECPublicKey pubkey = keypare.publicKey;
        final ECPrivateKey prikey = keypare.privateKey;
        final line = [
          strinifyPublicKey(pubkey),
          strinifyPrivateKey(prikey),
          pubkey.Q.x.toBigInteger().toRadixString(16),
          pubkey.Q.y.toBigInteger().toRadixString(16)
        ];
        final row = line.join(',');
        lines.add(row);
      }
      final txt = lines.join('\n');
      f.writeAsStringSync(txt);
      expect(true, equals(true));
    });
    test('Save and restore private key', (){
      final local_private = 'eaa692953a60ff85beecdf9647807f5e1bd665aa342c3c1d893b54bccf816ff5';
      final remote_public = '02766171786852c788bfac4622b302b1c42ca77e3bfdabc56454a4ca5647ac4eba';
      final enc = 'd5dTsgku25ylogZ7Yjs=';
      final iv = 'MRz0cLx8QL4=';
      final raw = privateDecrypt(local_private, remote_public, enc, iv);
      print('raw: ${raw}');
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
    test('Make request', () async {
      final convert.Utf8Encoder encoder = new convert.Utf8Encoder();
      final remote_pubkey = '02be8d8a7b5056de7a7074236100d094ebe86cce33d62469956203022af1f3e556';
      final my_kp = generateKeyPair();
      final data = 'abcdefg';
      final str_pri_key = strinifyPrivateKey(my_kp.privateKey);
      final str_pub_key = strinifyPublicKey(my_kp.publicKey);
      final enced = pubkeyEncryptRaw(str_pri_key, remote_pubkey, new Uint8List.fromList(encoder.convert(data)));
      final data_arr = new List<int>();
      data_arr.addAll(encoder.convert(str_pub_key));
      data_arr.addAll(enced['enc'].toList());
      print(convert.base64.encode(data_arr));
      expect(true, true);
    });
    test('Encrypt and Decrypt', (){
      int micro_seconds = 0;
      for(var i=0;i<10;i++){
        final alic_pubkey = '5cb38e0c76f2b28e112e78d96d46e79b04585f17c3bb81a11ad3ad327d9ccaf815b0d2c770fd31c7224671378d7129cdd3dba97ca1efd016e2a580048c6eec46';
        final alic_prikey = '9717f155a64b67e5aa22a9552824237119a373b84ffe62eb435cac6581099767';
        var bob = generateKeyPair();
        var raw_str = '测试测试测试';
        final t1 = new DateTime.now().millisecondsSinceEpoch;
        var enc_map = pubkeyEncrypt(alic_prikey, strinifyPublicKey(bob.publicKey), raw_str);
        micro_seconds += (new DateTime.now().millisecondsSinceEpoch - t1);
        var enc_str = enc_map['enc'];
        var iv = enc_map['iv'];
        var decryptd = privateDecrypt(strinifyPrivateKey(bob.privateKey), alic_pubkey, enc_str);
        print('d:${decryptd}');
        expect(raw_str, equals(decryptd));
      }
      print('avg: ${micro_seconds/100} ms');
      
    });
  });

}