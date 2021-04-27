package dev.o1c.jcryptobox;

import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;

import static org.junit.jupiter.api.Assertions.*;

class BoxTest {
    @Test
    void smokeTest() {
        Box box = Box.random();
        MessageDigest digest = SecurityLevel.SECRET.getMessageDigest();
        byte[] message = getClass().getName().getBytes(StandardCharsets.UTF_8);
        byte[] nonce = digest.digest(message);
        byte[] boxed = box.box(nonce, message);
        assertArrayEquals(message, box.open(nonce, boxed));

        assertThrows(IllegalArgumentException.class, () -> box.open(new byte[nonce.length], boxed));
        assertThrows(IllegalArgumentException.class, () -> box.open(nonce, boxed, 0, boxed.length - 1));
        assertArrayEquals(message, box.open(nonce, boxed, 0, boxed.length));
    }

    @Test
    void giftExchange() {
        KeyPair alice = Box.generateKeyPair();
        KeyPair bob = Box.generateKeyPair();
        byte[] messageAtoB = "Bob, please enjoy this gift!".getBytes(StandardCharsets.UTF_8);
        byte[] messageBtoA = "Alice, thanks for the gift!".getBytes(StandardCharsets.UTF_8);
        byte[] nonce = new byte[Long.BYTES];
        ByteBuffer.wrap(nonce).putLong(System.currentTimeMillis());
        byte[] bobGift = Box.boxing(alice, bob.getPublic()).box(nonce, messageAtoB);
        byte[] aliceGift = Box.boxing(bob, alice.getPublic()).box(nonce, messageBtoA);
        assertArrayEquals(messageAtoB, Box.opening(bob, alice.getPublic()).open(nonce, bobGift));
        assertArrayEquals(messageBtoA, Box.opening(alice, bob.getPublic()).open(nonce, aliceGift));
    }

    @Test
    void sealedBoxSmokeTest() {
        KeyPair alice = Box.generateKeyPair();
        Box.Seal box = Box.sealing(alice.getPublic());
        byte[] message = "Hello, Alice, this is an anonymous message :)".getBytes(StandardCharsets.UTF_8);
        byte[] seal = box.seal(message);
        assertArrayEquals(message, Box.unsealing(alice).unseal(seal));

        KeyPair bob = Box.generateKeyPair();
        Throwable cause = assertThrows(IllegalArgumentException.class, () -> Box.unsealing(bob).unseal(seal)).getCause();
        assertTrue(cause instanceof AEADBadTagException);
    }
}