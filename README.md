# JCryptoBox

JCryptoBox is a simple cryptography facade inspired by NaCl and libsodium.
The central concept exposed is the idea of boxing and opening boxed data.

## Usage

```java
import dev.o1c.jcryptobox.Box;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

class Example {
    void sealedBox() {
        var alice = Box.generateKeyPair();
        var message = "Hello, Alice!".getBytes(StandardCharsets.UTF_8);
        var sealedBox = Box.seal(alice.getPublic(), message);

        var decrypted = Box.unseal(alice, sealedBox);
        System.out.println(new String(decrypted, StandardCharsets.UTF_8));
    }

    void box() {
        var alice = Box.generateKeyPair();
        var bob = Box.generateKeyPair();
        // nonce can be any length but can only be used once per key
        var nonce = new byte[16];
        SecureRandom.getInstanceStrong().nextBytes(nonce);
        // or some sequential source with networking, etc.
        var message1 = "Hello, Bob! ~Alice".getBytes(StandardCharsets.UTF_8);
        var box1 = Box.box(alice, bob.getPublic(), nonce, message1);
        var decrypted1 = Box.open(bob, alice.getPublic(), nonce, box1);

        SecureRandom.getInstanceStrong().nextBytes(nonce);
        var message2 = "Greetings, Alice! ~Bob".getBytes(StandardCharsets.UTF_8);
        var box2 = Box.box(bob, alice.getPublic(), nonce, message2);
        var decrypted2 = Box.open(alice, bob.getPublic(), nonce, box2);
    }
}
```
