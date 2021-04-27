# JCryptoBox

JCryptoBox is a Java cryptographic facade API inspired by [NaCl](https://nacl.cr.yp.to/) and [libsodium](https://doc.libsodium.org/).
JCryptoBox uses cryptographic algorithms compliant with NIST FIPS 140 recommendations and works with or without a certified FIPS Java cryptography library such as [BouncyCastle](https://www.bouncycastle.org/fips-java/).
Cryptographic APIs are exposed via `Box`.
By default, boxes provide 128-bit security, and this can be configured to default to 256-bit security.

## Usage

JCryptoBox is published to Maven Central and can be added to a normal Apache Maven build with the following dependency:

```xml
<dependency>
    <groupId>dev.o1c</groupId>
    <artifactId>jcryptobox</artifactId>
    <version>1.0</version>
</dependency>
```

### Key Generation

Public and private keys can be generated via `Box.generateKeyPair()`.
By default, these are 256-bit ECDH keys using the standard NIST P.256 curve parameters.
In top secret security mode, this uses NIST P.521.
Keys can also be imported through standard Java cryptographic APIs, though that is an advanced topic.

### Encryption

Boxes provide mutual authentication and confidentiality of messages sent between two principals.
To encrypt a message from a sender to a recipient, a box is constructed from `Box.boxing()`.
To decrypt a message from a sender to a recipient, a box is constructed from `Box.opening()`.

Sealed boxes provide confidentiality and integrity of a message sent from an anonymous sender to a known recipient principal.
These can be constructed via `Box.sealing()` and `Box.unsealing()` for encryption and decryption respectively.

## Export Notice

This distribution includes cryptographic software.
The country in which you currently reside may have restrictions on the import, possession, use, and/or re-export to another country, of encryption software.
BEFORE using any encryption software, please check your country's laws, regulations and policies concerning the import, possession, or use, and re-export of encryption software, to see if this is permitted.
See https://www.wassenaar.org for more information.
