package dev.o1c.jcryptobox;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Objects;

public class BoxFactory {
    private final KeyAgreement keyAgreement;
    private final PublicKey publicKey;
    private final byte[] encodedKey;

    private BoxFactory(KeyPair keyPair) {
        keyAgreement = SecurityLevel.getDefault().getKeyAgreement();
        publicKey = keyPair.getPublic();
        encodedKey = publicKey.getEncoded();
        try {
            keyAgreement.init(keyPair.getPrivate());
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static BoxFactory getRandom() {
        return new BoxFactory(SecurityLevel.getDefault().getKeyPairGenerator().generateKeyPair());
    }

    public static BoxFactory fromKeyPair(KeyPair keyPair) {
        Objects.requireNonNull(keyPair);
        return new BoxFactory(keyPair);
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void box(PublicKey recipient, byte[] nonce, byte[] input, int inOffset, int inLength,
                    byte[] output, int outOffset) {
        generateSecretBox(recipient).box(nonce, input, inOffset, inLength, output, outOffset);
    }

    public byte[] box(PublicKey recipient, byte[] nonce, byte[] message, int offset, int length) {
        return generateSecretBox(recipient).box(nonce, message, offset, length);
    }

    public byte[] box(PublicKey recipient, byte[] nonce, byte[] message) {
        return box(recipient, nonce, message, 0, message.length);
    }

    public void open(PublicKey sender, byte[] nonce, byte[] input, int inOffset, int inLength, byte[] output, int outOffset) {
        recoverSecretBox(sender).open(nonce, input, inOffset, inLength, output, outOffset);
    }

    public byte[] open(PublicKey sender, byte[] nonce, byte[] box, int offset, int length) {
        return recoverSecretBox(sender).open(nonce, box, offset, length);
    }

    public byte[] open(PublicKey sender, byte[] nonce, byte[] box) {
        return open(sender, nonce, box, 0, box.length);
    }

    public void unseal(byte[] input, int inOffset, int inLength, byte[] output, int outOffset) {
        int keyLength = Byte.toUnsignedInt(input[inOffset]);
        int boxLength = inLength - 1 - keyLength;
        if (boxLength < SecretBoxFactory.getTagLength()) {
            throw new IllegalArgumentException("Sealed box too small");
        }
        KeySpec keySpec = new X509EncodedKeySpec(Arrays.copyOfRange(input, inOffset + 1, inOffset + 1 + keyLength));
        PublicKey sealKey;
        try {
            sealKey = SecurityLevel.getDefault().getKeyFactory().generatePublic(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
        MessageDigest digest = SecurityLevel.getDefault().getMessageDigest();
        digest.update(input, inOffset + 1, keyLength);
        digest.update(encodedKey);
        byte[] nonce = digest.digest();

        open(sealKey, nonce, input, inOffset + 1 + keyLength, boxLength, output, outOffset);
    }

    public byte[] unseal(byte[] sealedBox, int offset, int length) {
        int messageLength = length - 1 - encodedKey.length - SecretBoxFactory.getTagLength();
        if (messageLength < 0) {
            throw new IllegalArgumentException("Sealed box too small");
        }
        byte[] message = new byte[messageLength];
        unseal(sealedBox, offset, length, message, 0);
        return message;
    }

    public byte[] unseal(byte[] sealedBox) {
        return unseal(sealedBox, 0, sealedBox.length);
    }

    private SecretBoxFactory generateSecretBox(PublicKey recipient) {
        Mac kdf = initKDF(recipient);
        kdf.update(encodedKey);
        kdf.update(recipient.getEncoded());
        byte[] mac = kdf.doFinal();
        SecretKeySpec key = new SecretKeySpec(mac, 0, mac.length / 2, "AES");
        return SecretBoxFactory.fromSecretKey(key);
    }

    private SecretBoxFactory recoverSecretBox(PublicKey sender) {
        Mac kdf = initKDF(sender);
        kdf.update(sender.getEncoded());
        kdf.update(encodedKey);
        byte[] mac = kdf.doFinal();
        SecretKeySpec key = new SecretKeySpec(mac, 0, mac.length / 2, "AES");
        return SecretBoxFactory.fromSecretKey(key);
    }

    private Mac initKDF(PublicKey peerKey) {
        try {
            keyAgreement.doPhase(peerKey, true);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
        Mac kdf = SecurityLevel.getDefault().getMac();
        try {
            kdf.init(new SecretKeySpec(keyAgreement.generateSecret(), "KDF"));
        } catch (InvalidKeyException e) {
            throw new IllegalStateException(e);
        }
        return kdf;
    }

}
