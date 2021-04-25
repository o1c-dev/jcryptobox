package dev.o1c.jcryptobox;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Objects;

/**
 * Toolkit for authenticated public key and secret key cryptography. Data can be boxed to provide confidentiality
 * and authenticity which can only be opened by intended recipients.
 */
public class Box {
    public static final int TAG_LENGTH = 16;
    private static final int TAG_SIZE = 128;

    private final SecretKey key;

    private Box(SecretKey key) {
        this.key = key;
    }

    public void box(byte[] nonce, byte[] input, int inOffset, int inLength, byte[] output, int outOffset) {
        Cipher cipher = SecurityLevel.getDefault().getCipher();
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_SIZE, nonce));
            cipher.doFinal(input, inOffset, inLength, output, outOffset);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public byte[] box(byte[] nonce, byte[] message, int offset, int length) {
        byte[] box = new byte[length + TAG_LENGTH];
        box(nonce, message, offset, length, box, 0);
        return box;
    }

    public byte[] box(byte[] nonce, byte[] message) {
        return box(nonce, message, 0, message.length);
    }

    public void open(byte[] nonce, byte[] input, int inOffset, int inLength, byte[] output, int outOffset) {
        Cipher cipher = SecurityLevel.getDefault().getCipher();
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_SIZE, nonce));
            cipher.doFinal(input, inOffset, inLength, output, outOffset);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public byte[] open(byte[] nonce, byte[] box, int offset, int length) {
        Objects.requireNonNull(box);
        byte[] message = new byte[length - TAG_LENGTH];
        open(nonce, box, offset, length, message, 0);
        return message;
    }

    public byte[] open(byte[] nonce, byte[] box) {
        Objects.requireNonNull(box);
        return open(nonce, box, 0, box.length);
    }

    /**
     * Initializes a box to box data from the provided sender to the provided recipient.
     */
    public static Box boxing(KeyPair senderKeyPair, PublicKey recipientKey) {
        return fromKeyExchange(senderKeyPair, recipientKey, true);
    }

    /**
     * Initializes a box to open data from the provided sender to the provided recipient.
     */
    public static Box opening(KeyPair recipientKeyPair, PublicKey senderKey) {
        return fromKeyExchange(recipientKeyPair, senderKey, false);
    }

    /**
     * Generates a random public and private keypair.
     */
    public static KeyPair generateKeyPair() {
        return SecurityLevel.getDefault().getKeyPairGenerator().generateKeyPair();
    }

    static Box random() {
        return new Box(SecurityLevel.getDefault().getKeyGenerator().generateKey());
    }

    private static Box fromKeyExchange(KeyPair self, PublicKey peer, boolean isSender) {
        SecurityLevel securityLevel = SecurityLevel.getDefault();
        KeyAgreement keyAgreement = securityLevel.getKeyAgreement();
        try {
            keyAgreement.init(self.getPrivate());
            keyAgreement.doPhase(peer, true);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
        SecretKey sharedKey = new SecretKeySpec(keyAgreement.generateSecret(), securityLevel.getKdfMacAlgorithm());
        Mac kdf = securityLevel.getMac();
        try {
            kdf.init(sharedKey);
        } catch (InvalidKeyException e) {
            throw new IllegalStateException(e);
        }
        if (isSender) {
            kdf.update(self.getPublic().getEncoded());
            kdf.update(peer.getEncoded());
        } else {
            kdf.update(peer.getEncoded());
            kdf.update(self.getPublic().getEncoded());
        }
        byte[] mac = kdf.doFinal();
        SecretKey key = new SecretKeySpec(mac, 0, mac.length / 2, "AES");
        return new Box(key);
    }
}
