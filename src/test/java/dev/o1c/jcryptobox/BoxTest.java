package dev.o1c.jcryptobox;

import org.junit.Test;

import javax.crypto.AEADBadTagException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class BoxTest {

    private final Box alice = new Box();
    private final Box bob = new Box();

    @Test
    public void boxSmokeTest() throws Exception {
        byte[] message = "Hello, Bob! This is Alice".getBytes(StandardCharsets.UTF_8);
        byte[] nonce = new byte[12];
        SecureRandom.getInstanceStrong().nextBytes(nonce);

        byte[] box = alice.box(bob.getPublicKey(), nonce, message);
        assertArrayEquals(message, bob.open(alice.getPublicKey(), nonce, box));
    }

    @Test
    public void sealSmokeTest() {
        byte[] message = "Hello, Alice, this is an anonymous message :)".getBytes(StandardCharsets.UTF_8);

        byte[] sealedBox = Box.seal(alice.getPublicKey(), message);
        assertArrayEquals(message, alice.open(sealedBox));

        Throwable cause = assertThrows(IllegalArgumentException.class, () -> bob.open(sealedBox)).getCause();
        assertTrue(cause instanceof AEADBadTagException);
    }
}
