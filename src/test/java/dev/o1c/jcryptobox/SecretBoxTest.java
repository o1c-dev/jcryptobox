package dev.o1c.jcryptobox;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import static org.junit.Assert.assertArrayEquals;

public class SecretBoxTest {

    @Test
    public void smokeTest() throws Exception {
        byte[] key = new byte[32];
        byte[] nonce = new byte[32];
        SecureRandom random = SecureRandom.getInstanceStrong();
        random.nextBytes(key);
        random.nextBytes(nonce);
        byte[] message = "Hello, world!".getBytes(StandardCharsets.UTF_8);

        assertArrayEquals(message, SecretBox.open(key, nonce, SecretBox.box(key, nonce, message)));
    }

}