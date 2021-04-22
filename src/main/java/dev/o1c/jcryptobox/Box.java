package dev.o1c.jcryptobox;

import javax.crypto.AEADBadTagException;
import javax.crypto.KeyAgreement;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

public class Box {

    public static KeyPair generateKeyPair() {
        KeyPairGenerator keyPairGenerator = getKeyPairGenerator();
        keyPairGenerator.initialize(256);
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] box(KeyPair sender, PublicKey recipient, byte[] nonce, byte[] message) {
        validateArgs(sender, recipient);
        ECPublicKey senderKey = (ECPublicKey) sender.getPublic();
        ECPublicKey recipientKey = (ECPublicKey) recipient;
        MessageDigest sha256 = getSha256();

        sha256.update(generateSharedSecret(recipient, sender.getPrivate()));
        sha256.update(NistCurve.compress(senderKey));
        sha256.update(NistCurve.compress(recipientKey));
        byte[] sharedKey = sha256.digest();

        return SecretBox.box(sharedKey, nonce, message);
    }

    public static byte[] open(KeyPair recipient, PublicKey sender, byte[] nonce, byte[] box) throws AEADBadTagException {
        validateArgs(recipient, sender);
        ECPublicKey recipientKey = (ECPublicKey) recipient.getPublic();
        ECPublicKey senderKey = (ECPublicKey) sender;
        MessageDigest sha256 = getSha256();

        sha256.update(generateSharedSecret(senderKey, recipient.getPrivate()));
        sha256.update(NistCurve.compress(senderKey));
        sha256.update(NistCurve.compress(recipientKey));
        byte[] sharedKey = sha256.digest();

        return SecretBox.open(sharedKey, nonce, box);
    }

    public static byte[] seal(PublicKey recipient, byte[] message) {
        if (!(recipient instanceof ECPublicKey)) {
            throw new IllegalArgumentException("Recipient key must be an EC key");
        }
        ECPublicKey recipientKey = (ECPublicKey) recipient;
        byte[] recipientBytes = NistCurve.compress(recipientKey.getW(), recipientKey.getParams().getCurve());
        KeyPair sender = generateKeyPair();
        ECPublicKey senderKey = (ECPublicKey) sender.getPublic();
        byte[] senderBytes = NistCurve.compress(senderKey);
        MessageDigest sha256 = getSha256();
        sha256.update(senderBytes);
        sha256.update(recipientBytes);
        byte[] nonce = sha256.digest();

        sha256.reset();
        sha256.update(generateSharedSecret(recipient, sender.getPrivate()));
        sha256.update(senderBytes);
        sha256.update(recipientBytes);
        byte[] sharedKey = sha256.digest();

        byte[] box = Arrays.copyOf(senderBytes, senderBytes.length + message.length + SecretBox.TAG_BYTES);
        SecretBox.box(sharedKey, nonce, message, 0, message.length, box, senderBytes.length);
        return box;
    }

    public static byte[] unseal(KeyPair recipient, byte[] sealedBox) throws AEADBadTagException {
        if (!(recipient.getPrivate() instanceof ECPrivateKey)) {
            throw new IllegalArgumentException("Recipient key must be an EC key");
        }
        ECPublicKey recipientKey = (ECPublicKey) recipient.getPublic();
        byte[] recipientBytes = NistCurve.compress(recipientKey.getW(), recipientKey.getParams().getCurve());
        byte[] senderBytes = Arrays.copyOf(sealedBox, recipientBytes.length);
        // TODO: determine NistCurve from recipient params instead of hard coding
        ECPublicKey senderKey = NistCurve.P256.decodeKey(senderBytes);

        MessageDigest sha256 = getSha256();
        sha256.update(senderBytes);
        sha256.update(recipientBytes);
        byte[] nonce = sha256.digest();

        sha256.reset();
        sha256.update(generateSharedSecret(senderKey, recipient.getPrivate()));
        sha256.update(senderBytes);
        sha256.update(recipientBytes);
        byte[] sharedKey = sha256.digest();

        byte[] message = new byte[sealedBox.length - senderBytes.length - SecretBox.TAG_BYTES];
        SecretBox.open(sharedKey, nonce, sealedBox, senderBytes.length, message.length, message, 0);
        return message;
    }

    private static void validateArgs(KeyPair keyPair, PublicKey publicKey) {
        if (!(keyPair.getPrivate() instanceof ECPrivateKey && publicKey instanceof ECPublicKey)) {
            throw new IllegalArgumentException("Sender and recipient must be EC keys");
        }
        try {
            NistCurve.validatePublicKey((ECPublicKey) publicKey, (ECPrivateKey) keyPair.getPrivate());
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private static KeyPairGenerator getKeyPairGenerator() {
        try {
            return KeyPairGenerator.getInstance("EC");
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

    private static byte[] generateSharedSecret(PublicKey publicKey, PrivateKey privateKey) {
        try {
            KeyAgreement ecdh = KeyAgreement.getInstance("ECDH");
            ecdh.init(privateKey);
            ecdh.doPhase(publicKey, true);
            return ecdh.generateSecret();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
    }

}
