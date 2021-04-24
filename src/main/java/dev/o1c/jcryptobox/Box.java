package dev.o1c.jcryptobox;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class Box {

    private final KeyAgreement keyAgreement = Algorithms.getECDH();
    private final PublicKey publicKey;

    public Box() {
        this(generateKeyPair());
    }

    public Box(KeyPair keyPair) {
        publicKey = keyPair.getPublic();
        try {
            keyAgreement.init(keyPair.getPrivate());
        } catch (InvalidKeyException e) {
            throw new IllegalStateException(e);
        }
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
        return generateSecretBox(recipient).box(nonce, message);
    }

    public void open(PublicKey sender, byte[] nonce, byte[] input, int inOffset, int inLength, byte[] output, int outOffset) {
        recoverSecretBox(sender).open(nonce, input, inOffset, inLength, output, outOffset);
    }

    public byte[] open(PublicKey sender, byte[] nonce, byte[] box, int offset, int length) {
        return recoverSecretBox(sender).open(nonce, box, offset, length);
    }

    public byte[] open(PublicKey sender, byte[] nonce, byte[] box) {
        return recoverSecretBox(sender).open(nonce, box);
    }

    public byte[] open(byte[] sealedBox) {
        int ekLength = Byte.toUnsignedInt(sealedBox[0]);
        int messageLength = sealedBox.length - 1 - ekLength;
        if (messageLength < SecretBox.TAG_BYTES) {
            throw new IllegalArgumentException("Sealed box too small");
        }
        KeySpec keySpec = new X509EncodedKeySpec(Arrays.copyOfRange(sealedBox, 1, 1 + ekLength));
        PublicKey ephemeralKey;
        try {
            ephemeralKey = Algorithms.getECFactory().generatePublic(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }

        MessageDigest sha256 = Algorithms.getSha256();
        sha256.update(ephemeralKey.getEncoded());
        sha256.update(publicKey.getEncoded());
        byte[] nonce = sha256.digest();

        return open(ephemeralKey, nonce, sealedBox, 1 + ekLength, messageLength);
    }

    private SecretBox generateSecretBox(PublicKey recipient) {
        Mac kdf = initKDF(recipient);
        kdf.update(publicKey.getEncoded());
        kdf.update(recipient.getEncoded());
        return new SecretBox(kdf.doFinal());
    }

    private SecretBox recoverSecretBox(PublicKey sender) {
        Mac kdf = initKDF(sender);
        kdf.update(sender.getEncoded());
        kdf.update(publicKey.getEncoded());
        return new SecretBox(kdf.doFinal());
    }

    private Mac initKDF(PublicKey peerKey) {
        try {
            keyAgreement.doPhase(peerKey, true);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
        Mac kdf = Algorithms.getHmac();
        try {
            kdf.init(new SecretKeySpec(keyAgreement.generateSecret(), "KDF"));
        } catch (InvalidKeyException e) {
            throw new IllegalStateException(e);
        }
        return kdf;
    }

    public static byte[] seal(PublicKey recipient, byte[] message) {
        Box box = new Box();
        byte[] ephemeralKey = box.publicKey.getEncoded();
        MessageDigest sha256 = Algorithms.getSha256();
        sha256.update(ephemeralKey);

        int ekLength = ephemeralKey.length;
        byte[] seal = new byte[1 + ekLength + message.length + SecretBox.TAG_BYTES];
        seal[0] = (byte) ekLength;
        System.arraycopy(ephemeralKey, 0, seal, 1, ekLength);
        sha256.update(recipient.getEncoded());
        byte[] nonce = sha256.digest();

        box.box(recipient, nonce, message, 0, message.length, seal, 1 + ekLength);
        return seal;
    }

    public static KeyPair generateKeyPair() {
        KeyPairGenerator keyPairGenerator = Algorithms.getECGenerator();
        keyPairGenerator.initialize(256);
        return keyPairGenerator.generateKeyPair();
    }

}
