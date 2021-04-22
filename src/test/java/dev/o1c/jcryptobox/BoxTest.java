package dev.o1c.jcryptobox;

import org.junit.Before;
import org.junit.Test;

import javax.crypto.AEADBadTagException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.concurrent.ThreadLocalRandom;

import static org.junit.Assert.assertArrayEquals;

public class BoxTest {

    private KeyPair alice;
    private KeyPair bob;

    @Before
    public void setUp() {
        alice = Box.generateKeyPair();
        bob = Box.generateKeyPair();
    }

    @Test
    public void boxSmokeTest() throws AEADBadTagException {
        byte[] message = "Hello, Bob! This is Alice".getBytes(StandardCharsets.UTF_8);
        byte[] nonce = new byte[12];
        ThreadLocalRandom.current().nextBytes(nonce);
        byte[] box = Box.box(alice, bob.getPublic(), nonce, message);
        assertArrayEquals(message, Box.open(bob, alice.getPublic(), nonce, box));
    }
}
