package dev.o1c.jcryptobox;

import javax.crypto.AEADBadTagException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class Box {

    public static KeyPair generateKeyPair() {
        KeyPairGenerator keyPairGenerator = getECGenerator();
        keyPairGenerator.initialize(256);
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] box(KeyPair sender, PublicKey recipient, byte[] nonce, byte[] message) throws InvalidKeyException {
        byte[] key = generateBoxKey(sender, recipient);
        return SecretBox.box(key, nonce, message);
    }

    public static byte[] open(KeyPair recipient, PublicKey sender, byte[] nonce, byte[] box) throws AEADBadTagException, InvalidKeyException {
        byte[] key = generateBoxKey(sender, recipient);
        return SecretBox.open(key, nonce, box);
    }

    public static byte[] seal(PublicKey recipient, byte[] message) throws InvalidKeyException {
        KeyPair sender = generateKeyPair();
        byte[] key = generateBoxKey(sender, recipient);

        MessageDigest sha256 = getSha256();
        byte[] ephemeralKey = sender.getPublic().getEncoded();
        sha256.update(ephemeralKey);
        sha256.update(recipient.getEncoded());
        byte[] nonce = sha256.digest();

        int ekLength = ephemeralKey.length;
        byte[] box = new byte[1 + ekLength + message.length + SecretBox.TAG_BYTES];
        box[0] = (byte) ekLength;
        System.arraycopy(ephemeralKey, 0, box, 1, ekLength);
        SecretBox.box(key, nonce, message, 0, message.length, box, ekLength + 1);
        return box;
    }

    public static byte[] unseal(KeyPair recipient, byte[] sealedBox) throws AEADBadTagException, InvalidKeyException {
        int ekLength = Byte.toUnsignedInt(sealedBox[0]);
        int messageLength = sealedBox.length - 1 - ekLength - SecretBox.TAG_BYTES;
        if (messageLength < 0) {
            throw new IllegalArgumentException("Sealed box too small");
        }
        KeySpec ephemeralKey = new X509EncodedKeySpec(Arrays.copyOfRange(sealedBox, 1, 1 + ekLength));
        PublicKey publicKey;
        try {
            publicKey = getECFactory().generatePublic(ephemeralKey);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
        byte[] key = generateBoxKey(publicKey, recipient);

        MessageDigest sha256 = getSha256();
        sha256.update(publicKey.getEncoded());
        sha256.update(recipient.getPublic().getEncoded());
        byte[] nonce = sha256.digest();

        return SecretBox.open(key, nonce, sealedBox, 1 + ekLength, messageLength);
    }

    private static byte[] generateBoxKey(KeyPair sender, PublicKey recipient) throws InvalidKeyException {
        KeyAgreement kx = getECDH();
        kx.init(sender.getPrivate());
        kx.doPhase(recipient, true);
        Mac kdf = getHmac();
        kdf.init(new SecretKeySpec(kx.generateSecret(), "KDF"));
        kdf.update(sender.getPublic().getEncoded());
        kdf.update(recipient.getEncoded());
        return kdf.doFinal();
    }

    private static byte[] generateBoxKey(PublicKey sender, KeyPair recipient) throws InvalidKeyException {
        KeyAgreement kx = getECDH();
        kx.init(recipient.getPrivate());
        kx.doPhase(sender, true);
        Mac kdf = getHmac();
        kdf.init(new SecretKeySpec(kx.generateSecret(), "KDF"));
        kdf.update(sender.getEncoded());
        kdf.update(recipient.getPublic().getEncoded());
        return kdf.doFinal();
    }

    private static KeyAgreement getECDH() {
        try {
            return KeyAgreement.getInstance("ECDH");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static KeyFactory getECFactory() {
        try {
            return KeyFactory.getInstance("EC");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static KeyPairGenerator getECGenerator() {
        try {
            return KeyPairGenerator.getInstance("EC");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static Mac getHmac() {
        try {
            return Mac.getInstance("HmacSHA256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static MessageDigest getSha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

}
