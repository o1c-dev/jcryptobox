# JCryptoBox

JCryptoBox is a simple cryptography facade inspired by NaCl and libsodium that uses slightly more conservative cryptography standards (NIST FIPS 140).
Cryptographic APIs are exposed via `Box` and `SealedBox`.
By default, boxes provide 128-bit security.
This can be overridden via the system property `dev.o1c.jcryptobox.SecurityLevel` which can be set to `SECRET` (128-bit security) or `TOP_SECRET` (256-bit security).

## Usage

```java
import dev.o1c.jcryptobox.Box;
import dev.o1c.jcryptobox.SealedBox;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;

class Example {
    static void sealedBox() {
        KeyPair alice = Box.generateKeyPair();
        byte[] message = "Hello, Alice!".getBytes(StandardCharsets.UTF_8);
        byte[] sealedBox = SealedBox.to(alice.getPublic()).seal(message);

        byte[] decrypted = SealedBox.unseal(alice, sealedBox);
    }

    static void boxFactory() {
        KeyPair alice = Box.generateKeyPair();
        KeyPair bob = Box.generateKeyPair();

        // nonce can be any length but can only be used once per key
        byte[] nonce = new byte[16];
        SecureRandom random = SecureRandom.getInstanceStrong();
        random.nextBytes(nonce);
        // or some sequential source with networking, etc.
        byte[] message1 = "Hello, Bob! ~Alice".getBytes(StandardCharsets.UTF_8);
        byte[] box1 = Box.boxing(alice, bob.getPublic()).box(nonce, message1);
        byte[] decrypted1 = Box.opening(bob, alice.getPublic()).open(nonce, box1);

        random.nextBytes(nonce);
        byte[] message2 = "Greetings, Alice! ~Bob".getBytes(StandardCharsets.UTF_8);
        byte[] box2 = Box.boxing(bob, alice.getPublic()).box(nonce, message2);
        byte[] decrypted2 = Box.opening(alice, bob.getPublic()).open(nonce, box2);
    }
}
```
