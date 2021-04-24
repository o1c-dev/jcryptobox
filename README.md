# JCryptoBox

JCryptoBox is a simple cryptography facade inspired by NaCl and libsodium that uses slightly more conservative cryptography standards (NIST FIPS 140).
Cryptographic APIs are enabled via boxes.
Secret key cryptography is exposed via `SecretBoxFactory`.
Public key cryptography is exposed for mutual authentication via `BoxFactory` and for anonymous senders via `SealedBoxFactory`.
By default, boxes provide 128-bit security.
This can be overridden via the system property `dev.o1c.jcryptobox.SecurityLevel` which can be set to `SECRET` (128-bit security) or `TOP_SECRET` (256-bit security).

## Usage

```java
import dev.o1c.jcryptobox.BoxFactory;
import dev.o1c.jcryptobox.SealedBoxFactory;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.SecureRandom;

class Example {
    static void sealedBox() {
        BoxFactory alice = BoxFactory.getRandom();
        PublicKey aliceKey = alice.getPublicKey();
        SealedBoxFactory aliceFactory = SealedBoxFactory.fromRecipientKey(aliceKey);
        byte[] message = "Hello, Alice!".getBytes(StandardCharsets.UTF_8);
        byte[] sealedBox = aliceFactory.seal(message);

        byte[] decrypted = alice.unseal(sealedBox);
    }

    static void boxFactory() {
        BoxFactory alice = BoxFactory.getRandom();
        PublicKey alicePublicKey = alice.getPublicKey();
        BoxFactory bob = BoxFactory.getRandom();
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
