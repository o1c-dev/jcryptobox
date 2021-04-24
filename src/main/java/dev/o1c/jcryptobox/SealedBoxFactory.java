package dev.o1c.jcryptobox;

import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.Objects;

public class SealedBoxFactory {
    private final PublicKey recipientKey;
    private final byte[] encodedKey;

    private SealedBoxFactory(PublicKey recipientKey) {
        this.recipientKey = recipientKey;
        encodedKey = recipientKey.getEncoded();
    }

    public static SealedBoxFactory fromRecipientKey(PublicKey recipientKey) {
        Objects.requireNonNull(recipientKey);
        return new SealedBoxFactory(recipientKey);
    }

    public void seal(byte[] input, int inOffset, int inLength, byte[] output, int outOffset) {
        BoxFactory seal = BoxFactory.getRandom();
        byte[] sealKey = seal.getPublicKey().getEncoded();
        int keyLength = sealKey.length;
        if (output.length - outOffset < 1 + keyLength + inLength + SecretBoxFactory.getTagLength()) {
            throw new IllegalArgumentException("Output buffer too short");
        }
        output[outOffset] = (byte) keyLength;
        System.arraycopy(sealKey, 0, output, outOffset + 1, keyLength);

        MessageDigest digest = SecurityLevel.getDefault().getMessageDigest();
        digest.update(sealKey);
        digest.update(encodedKey);
        byte[] nonce = digest.digest();

        seal.box(recipientKey, nonce, input, inOffset, inLength, output, outOffset + 1 + keyLength);
    }

    public byte[] seal(byte[] message, int offset, int length) {
        byte[] box = new byte[1 + length + encodedKey.length + SecretBoxFactory.getTagLength()];
        seal(message, offset, length, box, 0);
        return box;
    }

    public byte[] seal(byte[] message) {
        return seal(message, 0, message.length);
    }

}
