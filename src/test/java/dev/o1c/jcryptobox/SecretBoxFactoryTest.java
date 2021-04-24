package dev.o1c.jcryptobox;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import static org.junit.jupiter.api.Assertions.*;

class SecretBoxFactoryTest {

    @Test
    void smokeTest() throws Exception {
        SecretBoxFactory key = SecretBoxFactory.getRandom();
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] message = "Hello, world!".getBytes(StandardCharsets.UTF_8);
        byte[] nonce = sha256.digest(message);

        assertArrayEquals(message, key.open(nonce, key.box(nonce, message)));
    }

}