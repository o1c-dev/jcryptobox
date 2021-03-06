# JCryptoBox

JCryptoBox is a Java cryptographic facade API inspired by [NaCl](https://nacl.cr.yp.to/) and [libsodium](https://doc.libsodium.org/).
JCryptoBox uses cryptographic algorithms compliant with NIST FIPS 140 recommendations and works with or without a certified FIPS Java cryptography library such as [BouncyCastle](https://www.bouncycastle.org/fips-java/).
Cryptographic APIs are exposed via [`JCryptoBox`](https://javadoc.io/static/dev.o1c/jcryptobox/1.0/dev/o1c/jcryptobox/JCryptoBox.html).
By default, boxes provide 128-bit security, and this can be configured to default to 256-bit security.

## Usage

JCryptoBox is published to Maven Central and GitHub Packages and can be added to a normal Apache Maven build with the following dependency:

```xml
<dependency>
    <groupId>dev.o1c</groupId>
    <artifactId>jcryptobox</artifactId>
    <version>1.0</version>
</dependency>
```

API documentation is [available online](https://javadoc.io/doc/dev.o1c/jcryptobox/1.0).

### Key Generation

Public and private keys can be generated via [`JCryptoBox.generateKeyPair()`](https://javadoc.io/static/dev.o1c/jcryptobox/1.0/dev/o1c/jcryptobox/JCryptoBox.html#generateKeyPair--).
By default, these are 256-bit ECDH keys using the standard NIST P.256 curve parameters.
In top secret security mode, this uses NIST P.521.
Keys can be encoded and decoded via [`JCryptoBox.encodeKey()`](https://javadoc.io/static/dev.o1c/jcryptobox/1.0/dev/o1c/jcryptobox/JCryptoBox.html#encodeKey-java.security.Key-) and [`JCryptoBox.decodePublicKey()`](https://javadoc.io/static/dev.o1c/jcryptobox/1.0/dev/o1c/jcryptobox/JCryptoBox.html#decodePublicKey-byte:A-)/[`JCryptoBox.decodePrivateKey()`](https://javadoc.io/static/dev.o1c/jcryptobox/1.0/dev/o1c/jcryptobox/JCryptoBox.html#decodePrivateKey-byte:A-) respectively.

### Encryption

Boxes provide mutual authentication and confidentiality of messages sent between two principals.
To encrypt a message from a sender to a recipient, a box is constructed from [`JCryptoBox.boxing()`](https://javadoc.io/static/dev.o1c/jcryptobox/1.0/dev/o1c/jcryptobox/JCryptoBox.html#boxing-java.security.KeyPair-java.security.PublicKey-).
To decrypt a message from a sender to a recipient, a box is constructed from [`JCryptoBox.opening()`](https://javadoc.io/static/dev.o1c/jcryptobox/1.0/dev/o1c/jcryptobox/JCryptoBox.html#opening-java.security.KeyPair-java.security.PublicKey-).

Sealed boxes provide confidentiality and integrity of a message sent from an anonymous sender to a known recipient principal.
These can be constructed via [`JCryptoBox.sealing()`](https://javadoc.io/static/dev.o1c/jcryptobox/1.0/dev/o1c/jcryptobox/JCryptoBox.html#sealing-java.security.PublicKey-) and [`JCryptoBox.unsealing()`](https://javadoc.io/static/dev.o1c/jcryptobox/1.0/dev/o1c/jcryptobox/JCryptoBox.html#unsealing-java.security.KeyPair-) for encryption and decryption respectively.

## Export Notice

This distribution includes cryptographic software.
The country in which you currently reside may have restrictions on the import, possession, use, and/or re-export to another country, of encryption software.
BEFORE using any encryption software, please check your country's laws, regulations and policies concerning the import, possession, or use, and re-export of encryption software, to see if this is permitted.
See https://www.wassenaar.org for more information.
