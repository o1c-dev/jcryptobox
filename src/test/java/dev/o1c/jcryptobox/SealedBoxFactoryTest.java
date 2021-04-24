package dev.o1c.jcryptobox;

import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class SealedBoxFactoryTest {
    @Test
    void smokeTest() {
        BoxFactory alice = BoxFactory.getRandom();
        SealedBoxFactory factory = SealedBoxFactory.fromRecipientKey(alice.getPublicKey());
        byte[] message = "Hello, Alice, this is an anonymous message :)".getBytes(StandardCharsets.UTF_8);
        byte[] seal = factory.seal(message);
        assertArrayEquals(message, alice.unseal(seal));

        BoxFactory bob = BoxFactory.getRandom();
        Throwable cause = assertThrows(IllegalArgumentException.class, () -> bob.unseal(seal)).getCause();
        assertTrue(cause instanceof AEADBadTagException);
    }
}