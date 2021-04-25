package dev.o1c.jcryptobox;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.*;

class SecurityLevelTest {

    private static final String SECURITY_LEVEL = SecurityLevel.class.getName();

    @BeforeEach
    void setUp() {
        System.clearProperty(SECURITY_LEVEL);
    }

    @AfterEach
    void tearDown() {
        System.clearProperty(SECURITY_LEVEL);
    }

    @Test
    void checkDefaultSecurityLevel() {
        assertSame(SecurityLevel.SECRET, SecurityLevel.getDefault());
        assertEquals(91, Box.generateKeyPair().getPublic().getEncoded().length);
    }

    @Test
    void checkOverriddenSecurityLevel() {
        System.setProperty(SECURITY_LEVEL, SecurityLevel.TOP_SECRET.name());
        assertSame(SecurityLevel.TOP_SECRET, SecurityLevel.getDefault());
        KeyPair alice = Box.generateKeyPair();
        PublicKey key = alice.getPublic();
        assertEquals(158, key.getEncoded().length);
        SealedBox box = SealedBox.to(key);
        byte[] message = SECURITY_LEVEL.getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(message, SealedBox.unseal(alice, box.seal(message)));
    }
}