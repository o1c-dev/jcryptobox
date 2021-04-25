package dev.o1c.jcryptobox;

import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.*;

class SealedBoxTest {
    @Test
    void smokeTest() {
        KeyPair alice = Box.generateKeyPair();
        SealedBox box = SealedBox.to(alice.getPublic());
        byte[] message = "Hello, Alice, this is an anonymous message :)".getBytes(StandardCharsets.UTF_8);
        byte[] seal = box.seal(message);
        assertArrayEquals(message, SealedBox.unseal(alice, seal));

        KeyPair bob = Box.generateKeyPair();
        Throwable cause = assertThrows(IllegalArgumentException.class, () -> SealedBox.unseal(bob, seal)).getCause();
        assertTrue(cause instanceof AEADBadTagException);
    }
}