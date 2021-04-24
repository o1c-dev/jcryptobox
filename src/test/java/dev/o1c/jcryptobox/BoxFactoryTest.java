package dev.o1c.jcryptobox;


import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

class BoxFactoryTest {

    private final BoxFactory alice = BoxFactory.getRandom();
    private final BoxFactory bob = BoxFactory.getRandom();

    @Test
    void smokeTest() throws Exception {
        byte[] message = "Hello, Bob! This is Alice".getBytes(StandardCharsets.UTF_8);
        byte[] nonce = new byte[12];
        SecureRandom.getInstanceStrong().nextBytes(nonce);

        byte[] box = alice.box(bob.getPublicKey(), nonce, message);
        assertArrayEquals(message, bob.open(alice.getPublicKey(), nonce, box));
    }
}
