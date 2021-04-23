# JCryptoBox

JCryptoBox is a simple cryptography facade inspired by NaCl and libsodium that uses slightly more conservative cryptography standards (NIST FIPS 140).
The central APIs are `Box` for public key cryptography and `SecretBox` for secret key cryptography.

## Usage

```java
import dev.o1c.jcryptobox.Box;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;

class Example {
    static void sealedBox() {
        // generate random keypair
        Box alice = new Box();
        // or obtain a KeyPair from Box.generateKeyPair()
        PublicKey aliceKey = alice.getPublicKey();
        byte[] message = "Hello, Alice!".getBytes(StandardCharsets.UTF_8);
        byte[] sealedBox = Box.seal(aliceKey, message);

        byte[] decrypted = alice.open(sealedBox);
    }

    static void box() {
        Box alice = new Box();
        PublicKey alicePublicKey = alice.getPublicKey();
        Box bob = new Box();
        PublicKey bobPublicKey = bob.getPublicKey();

        // nonce can be any length but can only be used once per key
        byte[] nonce = new byte[16];
        SecureRandom random = SecureRandom.getInstanceStrong();
        random.nextBytes(nonce);
        // or some sequential source with networking, etc.
        byte[] message1 = "Hello, Bob! ~Alice".getBytes(StandardCharsets.UTF_8);
        byte[] box1 = alice.box(bobPublicKey, nonce, message1);
        byte[] decrypted1 = bob.open(alicePublicKey, nonce, box1);

        random.nextBytes(nonce);
        byte[] message2 = "Greetings, Alice! ~Bob".getBytes(StandardCharsets.UTF_8);
        byte[] box2 = bob.box(alicePublicKey, nonce, message2);
        byte[] decrypted2 = alice.open(bobPublicKey, nonce, box2);
    }
}
```
