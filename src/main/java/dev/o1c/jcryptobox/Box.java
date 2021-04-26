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
 *
 * <p>Boxes uses authenticated encryption (AES-GCM) which relies on two input parameters: a <i>secret key</i> and a
 * <i>nonce.</i> Secret keys are automatically generated based on the given sender and recipient public keys.
 * <i>Public keys</i> and their corresponding <i>private keys</i> form a <i>keypair</i> where the public keys can be
 * safely shared with others while the private key should be kept safe.</p>
 * <p>The nonce parameter is an accompanying value to the secret key used in encrypting or decrypting a single
 * message/packet. <strong>A nonce must not be reused with the same key!</strong> Use of a nonce can either be
 * sequential numbers (useful in contexts where stable increasing numbers are guaranteed) or random byte strings.
 * While a nonce can be of arbitrary length, the effective size of a GCM nonce is 12 bytes as longer values are
 * hashed into a 12 byte value.</p>
 *
 * @see SealedBox
 */
public class Box {
    /**
     * Number of bytes needed to store the authentication tag at the end of a box.
     */
    public static final int TAG_LENGTH = 16;
    private static final int TAG_SIZE = 128;

    private final SecretKey key;

    private Box(SecretKey key) {
        this.key = key;
    }

    /**
     * Boxes the given slice of input data into the given output array at the given offset.
     *
     * @param nonce     nonce to use to encrypt the input data
     * @param input     array of bytes to read data to encrypt
     * @param inOffset  where in the input array to begin reading data
     * @param inLength  how many bytes to read and encrypt
     * @param output    array of bytes to write encrypted data to
     * @param outOffset where in the output array to begin writing data
     * @throws IllegalArgumentException if the output buffer is too small
     */
    public void box(byte[] nonce, byte[] input, int inOffset, int inLength, byte[] output, int outOffset) {
        Cipher cipher = SecurityLevel.getDefault().getCipher();
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_SIZE, nonce));
            cipher.doFinal(input, inOffset, inLength, output, outOffset);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * Boxes the given message slice and returns the boxed message.
     *
     * @param nonce   nonce to use to encrypt the input message
     * @param message array of bytes to read data to encrypt
     * @param offset  where in the message array to begin reading data to encrypt
     * @param length  how many bytes to read and encrypt
     * @return the boxed message
     */
    public byte[] box(byte[] nonce, byte[] message, int offset, int length) {
        byte[] box = new byte[length + TAG_LENGTH];
        box(nonce, message, offset, length, box, 0);
        return box;
    }

    /**
     * Boxes the given message bytes and returns the boxed message.
     *
     * @param nonce   nonce to use to encrypt the input message
     * @param message array of bytes to encrypt
     * @return the boxed message
     */
    public byte[] box(byte[] nonce, byte[] message) {
        return box(nonce, message, 0, message.length);
    }

    /**
     * Opens the given boxed input slice and writes the decrypted data to the given output array at the given offset.
     *
     * @param nonce     nonce used to encrypt the boxed message
     * @param input     array of bytes to read boxed data to decrypt
     * @param inOffset  where in the input array to begin reading data to decrypt
     * @param inLength  length of the boxed message in bytes (includes authentication tag)
     * @param output    array of bytes to write decrypted message to
     * @param outOffset where in the output array to begin writing decrypted data
     * @throws IllegalArgumentException if the boxed data cannot be successfully authenticated and decrypted or if the
     *                                  output buffer is too small
     */
    public void open(byte[] nonce, byte[] input, int inOffset, int inLength, byte[] output, int outOffset) {
        Cipher cipher = SecurityLevel.getDefault().getCipher();
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_SIZE, nonce));
            cipher.doFinal(input, inOffset, inLength, output, outOffset);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * Opens the given boxed message slice and returns the decrypted message.
     *
     * @param nonce  nonce used to encrypt the boxed message
     * @param box    array of bytes to read boxed data to decrypt
     * @param offset where in the input array to begin reading data to decrypt
     * @param length length of the boxed message in bytes (includes authentication tag)
     * @return the decrypted message
     * @throws IllegalArgumentException if the boxed data cannot be successfully authenticated and decrypted
     */
    public byte[] open(byte[] nonce, byte[] box, int offset, int length) {
        Objects.requireNonNull(box);
        byte[] message = new byte[length - TAG_LENGTH];
        open(nonce, box, offset, length, message, 0);
        return message;
    }

    /**
     * Opens the given boxed message and returns the decrypted message.
     *
     * @param nonce nonce used to encrypt the boxed message
     * @param box   array of boxed data to decrypt
     * @return the decrypted message
     * @throws IllegalArgumentException if the boxed data cannot be successfully authenticated and decrypted
     */
    public byte[] open(byte[] nonce, byte[] box) {
        Objects.requireNonNull(box);
        return open(nonce, box, 0, box.length);
    }

    /**
     * Initializes a box to box data from the provided sender to the provided recipient.
     *
     * @param senderKeyPair keypair of the principal sending the boxed data
     * @param recipientKey  public key of the principal opening the boxed data
     * @return a new box ready to encrypt data from the sender to the recipient
     */
    public static Box boxing(KeyPair senderKeyPair, PublicKey recipientKey) {
        return fromKeyExchange(senderKeyPair, recipientKey, true);
    }

    /**
     * Initializes a box to open data from the provided sender to the provided recipient.
     *
     * @param recipientKeyPair keypair of the principal opening the boxed data
     * @param senderKey        public key of the principal who sent the boxed data
     * @return a new box ready to decrypt data from the sender to the recipient
     */
    public static Box opening(KeyPair recipientKeyPair, PublicKey senderKey) {
        return fromKeyExchange(recipientKeyPair, senderKey, false);
    }

    /**
     * Generates a random public and private keypair.
     *
     * @return newly generated random keypair
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
