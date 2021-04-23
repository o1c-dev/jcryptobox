package dev.o1c.jcryptobox;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import static org.junit.Assert.assertArrayEquals;

public class SecretBoxTest {

    @Test
    public void smokeTest() throws Exception {
        SecretBox key = new SecretBox();
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] message = "Hello, world!".getBytes(StandardCharsets.UTF_8);
        byte[] nonce = sha256.digest(message);

        assertArrayEquals(message, key.open(nonce, key.box(nonce, message)));
    }

}