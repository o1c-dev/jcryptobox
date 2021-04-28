# JCryptoBox

JCryptoBox is a simple cryptography facade inspired by NaCl and libsodium that uses slightly more conservative cryptography standards (NIST FIPS 140).
Cryptographic APIs are exposed via the `JCryptoBox` class.
By default, boxes provide 128-bit security.
This can be overridden via the system property `dev.o1c.jcryptobox.SecurityLevel` which can be set to `SECRET` (128-bit security) or `TOP_SECRET` (256-bit security).

## Usage

JCryptoBox is published to Maven Central and can be added to a normal Apache Maven build with the following dependency:

```xml
<dependency>
    <groupId>dev.o1c</groupId>
    <artifactId>jcryptobox</artifactId>
    <version>1.0</version>
</dependency>
```

A quick overview of some APIs:

```java
import dev.o1c.jcryptobox.JCryptoBox;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;

class Example {
    static void sealedBox() {
        KeyPair alice = JCryptoBox.generateKeyPair();
        byte[] message = "Hello, Alice!".getBytes(StandardCharsets.UTF_8);
        byte[] sealedBox = JCryptoBox.sealing(alice.getPublic()).seal(message);

        byte[] decrypted = JCryptoBox.unsealing(alice).unseal(sealedBox);
    }

    static void boxFactory() {
        KeyPair alice = JCryptoBox.generateKeyPair();
        KeyPair bob = JCryptoBox.generateKeyPair();

        // nonce can be any length but can only be used once per key
        byte[] nonce = new byte[16];
        SecureRandom random = SecureRandom.getInstanceStrong();
        random.nextBytes(nonce);
        // or some sequential source with networking, etc.
        byte[] message1 = "Hello, Bob! ~Alice".getBytes(StandardCharsets.UTF_8);
        byte[] box1 = JCryptoBox.boxing(alice, bob.getPublic()).box(nonce, message1);
        byte[] decrypted1 = JCryptoBox.opening(bob, alice.getPublic()).open(nonce, box1);

        random.nextBytes(nonce);
        byte[] message2 = "Greetings, Alice! ~Bob".getBytes(StandardCharsets.UTF_8);
        byte[] box2 = JCryptoBox.boxing(bob, alice.getPublic()).box(nonce, message2);
        byte[] decrypted2 = JCryptoBox.opening(alice, bob.getPublic()).open(nonce, box2);
    }
}
```

## Export Notice

This distribution includes cryptographic software.
The country in which you currently reside may have restrictions on the import, possession, use, and/or re-export to another country, of encryption software.
BEFORE using any encryption software, please check your country's laws, regulations and policies concerning the import, possession, or use, and re-export of encryption software, to see if this is permitted.
See https://www.wassenaar.org for more information.
