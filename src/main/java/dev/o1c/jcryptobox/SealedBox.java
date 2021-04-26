package dev.o1c.jcryptobox;

import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Objects;

/**
 * Provides anonymous public key cryptography to allow anonymous senders to box data to a known recipient public key.
 * Sealed boxes differ from a normal {@link Box} by including a randomly generated public key with the boxed message
 * that the recipient can use to unseal the box.
 *
 * @see Box
 */
public class SealedBox {
    private final PublicKey recipientKey;
    private final byte[] encodedKey;

    private SealedBox(PublicKey recipientKey) {
        this.recipientKey = recipientKey;
        encodedKey = recipientKey.getEncoded();
    }

    public void seal(byte[] input, int inOffset, int inLength, byte[] output, int outOffset) {
        int keyLength = encodedKey.length;
        if (output.length - outOffset < 1 + keyLength + inLength + Box.TAG_LENGTH) {
            throw new IllegalArgumentException("Output buffer too short");
        }

        KeyPair sealKeyPair = Box.generateKeyPair();
        Box box = Box.boxing(sealKeyPair, recipientKey);
        byte[] sealKey = sealKeyPair.getPublic().getEncoded();
        output[outOffset] = (byte) keyLength;
        System.arraycopy(sealKey, 0, output, outOffset + 1, keyLength);

        MessageDigest digest = SecurityLevel.getDefault().getMessageDigest();
        digest.update(sealKey);
        digest.update(encodedKey);
        byte[] nonce = digest.digest();

        box.box(nonce, input, inOffset, inLength, output, outOffset + 1 + keyLength);
    }

    public byte[] seal(byte[] message, int offset, int length) {
        byte[] box = new byte[1 + length + encodedKey.length + Box.TAG_LENGTH];
        seal(message, offset, length, box, 0);
        return box;
    }

    public byte[] seal(byte[] message) {
        return seal(message, 0, message.length);
    }

    public static SealedBox to(PublicKey recipientKey) {
        Objects.requireNonNull(recipientKey);
        return new SealedBox(recipientKey);
    }

    public static void unseal(KeyPair keyPair, byte[] input, int inOffset, int inLength, byte[] output, int outOffset) {
        int keyLength = Byte.toUnsignedInt(input[inOffset]);
        int boxLength = inLength - 1 - keyLength;
        if (boxLength < Box.TAG_LENGTH) {
            throw new IllegalArgumentException("Sealed box too small");
        }
        KeySpec keySpec = new X509EncodedKeySpec(Arrays.copyOfRange(input, inOffset + 1, inOffset + 1 + keyLength));
        SecurityLevel securityLevel = SecurityLevel.getDefault();
        PublicKey sealKey;
        try {
            sealKey = securityLevel.getKeyFactory().generatePublic(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
        Box box = Box.opening(keyPair, sealKey);

        MessageDigest digest = securityLevel.getMessageDigest();
        digest.update(input, inOffset + 1, keyLength);
        digest.update(keyPair.getPublic().getEncoded());
        byte[] nonce = digest.digest();

        box.open(nonce, input, inOffset + 1 + keyLength, boxLength, output, outOffset);
    }

    public static byte[] unseal(KeyPair keyPair, byte[] sealedBox, int offset, int length) {
        int messageLength = length - 1 - keyPair.getPublic().getEncoded().length - Box.TAG_LENGTH;
        if (messageLength < 0) {
            throw new IllegalArgumentException("Sealed box too small");
        }
        byte[] message = new byte[messageLength];
        unseal(keyPair, sealedBox, offset, length, message, 0);
        return message;
    }

    public static byte[] unseal(KeyPair keyPair, byte[] sealedBox) {
        return unseal(keyPair, sealedBox, 0, sealedBox.length);
    }

}
