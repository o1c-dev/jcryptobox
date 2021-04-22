package dev.o1c.jcryptobox;

import org.junit.Test;

import javax.crypto.AEADBadTagException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ThreadLocalRandom;

import static org.junit.Assert.*;

public class SecretBoxTest {

    @Test
    public void smokeTest() throws AEADBadTagException {
        byte[] key = new byte[32];
        byte[] nonce = new byte[32];
        ThreadLocalRandom.current().nextBytes(key);
        ThreadLocalRandom.current().nextBytes(nonce);
        byte[] message = "Hello, world!".getBytes(StandardCharsets.UTF_8);

        assertArrayEquals(message, SecretBox.open(key, nonce, SecretBox.box(key, nonce, message)));
    }

}