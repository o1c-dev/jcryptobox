package dev.o1c.jcryptobox;

import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class JCryptoBoxTest {
    @Test
    void smokeTest() {
        JCryptoBox box = JCryptoBox.random();
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
        KeyPair alice = JCryptoBox.generateKeyPair();
        KeyPair bob = JCryptoBox.generateKeyPair();
        byte[] messageAtoB = "Bob, please enjoy this gift!".getBytes(StandardCharsets.UTF_8);
        byte[] messageBtoA = "Alice, thanks for the gift!".getBytes(StandardCharsets.UTF_8);
        byte[] nonce = new byte[Long.BYTES];
        ByteBuffer.wrap(nonce).putLong(System.currentTimeMillis());
        byte[] bobGift = JCryptoBox.boxing(alice, bob.getPublic()).box(nonce, messageAtoB);
        byte[] aliceGift = JCryptoBox.boxing(bob, alice.getPublic()).box(nonce, messageBtoA);
        assertArrayEquals(messageAtoB, JCryptoBox.opening(bob, alice.getPublic()).open(nonce, bobGift));
        assertArrayEquals(messageBtoA, JCryptoBox.opening(alice, bob.getPublic()).open(nonce, aliceGift));
    }

    @Test
    void sealedBoxSmokeTest() {
        KeyPair alice = JCryptoBox.generateKeyPair();
        JCryptoBox.Seal box = JCryptoBox.sealing(alice.getPublic());
        byte[] message = "Hello, Alice, this is an anonymous message :)".getBytes(StandardCharsets.UTF_8);
        byte[] seal = box.seal(message);
        assertArrayEquals(message, JCryptoBox.unsealing(alice).unseal(seal));

        KeyPair bob = JCryptoBox.generateKeyPair();
        Throwable cause = assertThrows(IllegalArgumentException.class, () -> JCryptoBox.unsealing(bob).unseal(seal)).getCause();
        assertTrue(cause instanceof AEADBadTagException);
    }

    @Test
    void encodeDecodeKeyPair() {
        byte[] encodedPublicKey = Base64.getDecoder().decode(
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/6PxWKjIQWQfjDWOUXWD+bTbuU8CDA21UAZhYYr8WYl0Ca0r1bWbS0S9arYt55VnoVFiX/eMC54HLROJEOby1g==");
        PublicKey publicKey = JCryptoBox.decodePublicKey(encodedPublicKey);
        assertEquals("EC", publicKey.getAlgorithm());
        assertArrayEquals(encodedPublicKey, JCryptoBox.encodeKey(publicKey));
        byte[] encodedPrivateKey = Base64.getDecoder().decode(
                "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCDZTdwE4c8nT8T7GJKHBioG42YPURgk2p+KK3B0d0FAmA==");
        PrivateKey privateKey = JCryptoBox.decodePrivateKey(encodedPrivateKey);
        assertEquals("EC", privateKey.getAlgorithm());
        assertArrayEquals(encodedPrivateKey, JCryptoBox.encodeKey(privateKey));
    }
}