package dev.o1c.jcryptobox;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.GeneralSecurityException;
import java.util.Objects;

public class SecretBoxFactory {
    private static final int TAG_BYTES = 16;
    private static final int TAG_BITS = TAG_BYTES * Byte.SIZE;

    private final SecretKey key;

    SecretBoxFactory(SecretKey key) {
        this.key = key;
    }

    public static SecretBoxFactory getRandom() {
        return new SecretBoxFactory(SecurityLevel.getDefault().getKeyGenerator().generateKey());
    }

    public static SecretBoxFactory fromSecretKey(SecretKey key) {
        Objects.requireNonNull(key);
        return new SecretBoxFactory(key);
    }

    public static int getTagLength() {
        return TAG_BYTES;
    }

    public void box(byte[] nonce, byte[] input, int inOffset, int inLength, byte[] output, int outOffset) {
        Cipher cipher = SecurityLevel.getDefault().getCipher();
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce));
            cipher.doFinal(input, inOffset, inLength, output, outOffset);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public byte[] box(byte[] nonce, byte[] message, int offset, int length) {
        byte[] box = new byte[length + TAG_BYTES];
        box(nonce, message, offset, length, box, 0);
        return box;
    }

    public byte[] box(byte[] nonce, byte[] message) {
        return box(nonce, message, 0, message.length);
    }

    public void open(byte[] nonce, byte[] input, int inOffset, int inLength, byte[] output, int outOffset) {
        Cipher cipher = SecurityLevel.getDefault().getCipher();
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce));
            cipher.doFinal(input, inOffset, inLength, output, outOffset);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public byte[] open(byte[] nonce, byte[] box, int offset, int length) {
        Objects.requireNonNull(box);
        byte[] message = new byte[length - TAG_BYTES];
        open(nonce, box, offset, length, message, 0);
        return message;
    }

    public byte[] open(byte[] nonce, byte[] box) {
        Objects.requireNonNull(box);
        return open(nonce, box, 0, box.length);
    }

}
