package dev.o1c.jcryptobox;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

enum SecurityLevel {
    SECRET(128, 256, "HmacSHA256", "SHA-256"),
    TOP_SECRET(256, 521, "HmacSHA512", "SHA-512");

    private final int symmetricKeySize;
    private final int asymmetricKeySize;
    private final String kdfMacAlgorithm;
    private final String digestAlgorithm;

    SecurityLevel(int symmetricKeySize, int asymmetricKeySize, String kdfMacAlgorithm, String digestAlgorithm) {
        this.symmetricKeySize = symmetricKeySize;
        this.asymmetricKeySize = asymmetricKeySize;
        this.kdfMacAlgorithm = kdfMacAlgorithm;
        this.digestAlgorithm = digestAlgorithm;
    }

    static SecurityLevel getDefault() {
        return valueOf(System.getProperty(SecurityLevel.class.getName(), SECRET.name()));
    }

    Cipher getCipher() {
        try {
            return Cipher.getInstance("AES/GCM/NoPadding");
        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    String getKdfMacAlgorithm() {
        return kdfMacAlgorithm;
    }

    KeyGenerator getKeyGenerator() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(symmetricKeySize);
            return keyGenerator;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    KeyPairGenerator getKeyPairGenerator() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(asymmetricKeySize);
            return keyPairGenerator;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    KeyFactory getKeyFactory() {
        try {
            return KeyFactory.getInstance("EC");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    KeyAgreement getKeyAgreement() {
        try {
            return KeyAgreement.getInstance("ECDH");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    Mac getMac() {
        try {
            return Mac.getInstance(kdfMacAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    MessageDigest getMessageDigest() {
        try {
            return MessageDigest.getInstance(digestAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
