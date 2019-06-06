import 'package:secp256k1cipher/secp256k1cipher.dart';

void main(){
  var alic = generateKeyPair(); // Create Alic keypair
  var bob = generateKeyPair();  // Create Bob keypair
  var raw_str = 'Encrypt and decrypt data use secp256k1';  // This is what alic want to say to bob
  var enc_map = pubkeyEncrypt(strinifyPrivateKey(alic.privateKey), strinifyPublicKey(bob.publicKey), raw_str); // use alic's privatekey and bob's publickey means alic say to bob
  var enc_str = enc_map['enc']; // Get encrypted base64 string
  var iv = enc_map['iv'];       // Get random IV
  // next thing, you can send enc_str and IV via internet to bob
  var decryptd = privateDecrypt(strinifyPrivateKey(bob.privateKey), strinifyPublicKey(alic.publicKey), enc_str, iv); // use bob's privatekey and alic's publickey means bob can read message from alic
  print('alic say:${decryptd}');
}