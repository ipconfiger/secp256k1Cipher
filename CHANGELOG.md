Changelog
=========


#### Version 0.1.0 (2019-06-06)

* Add example code and this file.

#### Version 0.1.1 (2019-06-10)

* 1. sha256 compress the secret length to 32, just fix the salsa20 key langth;
* 2. Change IV to base64 string, will be shorter for transport;

### Version 0.1.2 (2019-06-21)
* 1. add uint8list encrypt decrypt support

### Version 0.1.3 (2019-07-02)
* 1. add strict check for point on curve
* 2. fix bug's on serialization of public key

### Version 0.1.4 (2019-07-03)
* 1. add compressed publickey support

### Version 0.1.5 (2019-07-03)
* 1. Change secret to encrypt key method to eliminate ambiguity;

### Version 0.1.6 (2019-07-11)
* 1. fix bugs when encrypt and decrypt unicode String