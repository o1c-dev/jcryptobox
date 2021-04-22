package dev.o1c.jcryptobox;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.BufferOverflowException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

public class SecretBox {

    public static final int TAG_BYTES = 16;
    private static final String KEY_ALGORITHM = "AES";

    public static void box(byte[] key, byte[] nonce, byte[] input, int inOffset, int inLength, byte[] output, int outOffset) {
        Objects.requireNonNull(key);
        Objects.requireNonNull(nonce);
        Objects.requireNonNull(input);
        Objects.requireNonNull(output);
        if (output.length - outOffset - TAG_BYTES < inLength) {
            throw new BufferOverflowException();
        }

        Cipher cipher = getAESCipher();
        try {
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, KEY_ALGORITHM), new GCMParameterSpec(TAG_BYTES * Byte.SIZE, nonce));
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new IllegalArgumentException(e);
        }
        try {
            cipher.doFinal(input, inOffset, inLength, output, outOffset);
        } catch (IllegalBlockSizeException | BadPaddingException | ShortBufferException e) {
            throw new IllegalStateException(e);
        }
    }

    public static byte[] box(byte[] key, byte[] nonce, byte[] message) {
        Objects.requireNonNull(key);
        Objects.requireNonNull(nonce);
        Objects.requireNonNull(message);

        byte[] box = new byte[message.length + TAG_BYTES];
        box(key, nonce, message, 0, message.length, box, 0);
        return box;
    }

    public static void open(byte[] key, byte[] nonce, byte[] input, int inOffset, int inLength, byte[] output, int outOffset) throws AEADBadTagException {
        Objects.requireNonNull(key);
        Objects.requireNonNull(nonce);
        Objects.requireNonNull(input);
        Objects.requireNonNull(output);
        if (output.length - outOffset + TAG_BYTES < inLength) {
            throw new BufferOverflowException();
        }

        Cipher cipher = getAESCipher();
        try {
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, KEY_ALGORITHM), new GCMParameterSpec(TAG_BYTES * Byte.SIZE, nonce));
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new IllegalArgumentException(e);
        }
        try {
            cipher.doFinal(input, inOffset, inLength, output, outOffset);
        } catch (AEADBadTagException e) {
            throw e;
        } catch (IllegalBlockSizeException | BadPaddingException | ShortBufferException e) {
            throw new IllegalStateException(e);
        }
    }

    public static byte[] open(byte[] key, byte[] nonce, byte[] secretBox) throws AEADBadTagException {
        Objects.requireNonNull(key);
        Objects.requireNonNull(nonce);
        Objects.requireNonNull(secretBox);

        byte[] message = new byte[secretBox.length - TAG_BYTES];
        open(key, nonce, secretBox, 0, secretBox.length, message, 0);
        return message;
    }

    private static Cipher getAESCipher() {
        try {
            return Cipher.getInstance("AES/GCM/NoPadding");
        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
