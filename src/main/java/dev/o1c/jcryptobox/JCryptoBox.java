package dev.o1c.jcryptobox;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
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
 * @see Seal
 * @see Unseal
 */
public class JCryptoBox {
    /**
     * Number of bytes needed to store the authentication tag at the end of a box.
     */
    public static final int TAG_LENGTH = 16;
    private static final int TAG_SIZE = 128;

    private final SecretKey key;

    private JCryptoBox(SecretKey key) {
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
     * @throws NullPointerException     if any arrays are null
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
     * @throws NullPointerException if any arrays are null
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
     * @throws NullPointerException if any args are null
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
     * @throws NullPointerException     if any arrays are null
     */
    public void open(byte[] nonce, byte[] input, int inOffset, int inLength, byte[] output, int outOffset) {
        Objects.requireNonNull(nonce);
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
     * @throws NullPointerException     if any arrays are null
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
     * @throws NullPointerException     if any args are null
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
     * @throws NullPointerException if any args are null
     * @see #opening(KeyPair, PublicKey)
     */
    public static JCryptoBox boxing(KeyPair senderKeyPair, PublicKey recipientKey) {
        Objects.requireNonNull(senderKeyPair);
        Objects.requireNonNull(recipientKey);
        return fromKeyExchange(senderKeyPair, recipientKey, true);
    }

    /**
     * Initializes a box to open data from the provided sender to the provided recipient.
     *
     * @param recipientKeyPair keypair of the principal opening the boxed data
     * @param senderKey        public key of the principal who sent the boxed data
     * @return a new box ready to decrypt data from the sender to the recipient
     * @throws NullPointerException if any args are null
     * @see #boxing(KeyPair, PublicKey)
     */
    public static JCryptoBox opening(KeyPair recipientKeyPair, PublicKey senderKey) {
        Objects.requireNonNull(recipientKeyPair);
        Objects.requireNonNull(senderKey);
        return fromKeyExchange(recipientKeyPair, senderKey, false);
    }

    /**
     * Creates a box to seal to the provided recipient key for creating sealed boxes.
     *
     * @param recipient public key of the principal receiving the sealed box
     * @return a new box seal ready to encrypt data to the recipient
     * @throws NullPointerException if the provided key is null
     * @see #unsealing(KeyPair)
     */
    public static Seal sealing(PublicKey recipient) {
        Objects.requireNonNull(recipient);
        return new Seal(recipient);
    }

    /**
     * Creates a box to unseal from the provided recipient keypair for decrypting sealed boxes sent to the recipient.
     *
     * @param recipient keypair of recipient of sealed boxes
     * @return a new box unseal ready to decrypt data to the recipient
     * @throws NullPointerException if the provided keypair is null
     * @see #sealing(PublicKey)
     */
    public static Unseal unsealing(KeyPair recipient) {
        Objects.requireNonNull(recipient);
        return new Unseal(recipient);
    }

    /**
     * Generates a random public and private keypair.
     *
     * @return newly generated random keypair
     */
    public static KeyPair generateKeyPair() {
        return SecurityLevel.getDefault().getKeyPairGenerator().generateKeyPair();
    }

    /**
     * Encodes a key into its default encoded format. For public keys, this format is suitable for
     * {@link X509EncodedKeySpec}, while private keys are formatted for {@link PKCS8EncodedKeySpec}.
     *
     * @param key key to encode
     * @return the encoded form of the key
     * @throws NullPointerException if the provided key is null
     */
    public static byte[] encodeKey(Key key) {
        Objects.requireNonNull(key);
        return key.getEncoded();
    }

    /**
     * Decodes an encoded public key.
     *
     * @param encodedPublicKey encoded key data to parse and decode
     * @return the decoded PublicKey
     * @throws IllegalArgumentException if the provided public key data is invalid
     * @throws NullPointerException     if the provided key is null
     */
    public static PublicKey decodePublicKey(byte[] encodedPublicKey) {
        KeySpec keySpec = new X509EncodedKeySpec(encodedPublicKey);
        try {
            return SecurityLevel.getDefault().getKeyFactory().generatePublic(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * Decodes an encoded private key.
     *
     * @param encodedPrivateKey encoded key data to parse and decode
     * @return the decoded PrivateKey
     * @throws IllegalArgumentException if the provided private key data is invalid
     * @throws NullPointerException     if the provided key is null
     */
    public static PrivateKey decodePrivateKey(byte[] encodedPrivateKey) {
        KeySpec keySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
        try {
            return SecurityLevel.getDefault().getKeyFactory().generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
    }

    static JCryptoBox random() {
        return new JCryptoBox(SecurityLevel.getDefault().getKeyGenerator().generateKey());
    }

    private static JCryptoBox fromKeyExchange(KeyPair self, PublicKey peer, boolean isSender) {
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
        return new JCryptoBox(key);
    }

    /**
     * Sealed boxes provide the ability for an anonymous sender to encrypt a message to a known recipient given their
     * public key. Sealed boxes differ from a {@linkplain JCryptoBox normal box} in that only the integrity of the message can be
     * verified by the recipient while normal boxes also verify sender identity. Messages are encrypted using ephemeral
     * public keys whose corresponding private keys are discarded. Without the private key used for a given message, the
     * sender cannot decrypt their own message later.
     *
     * @see JCryptoBox#sealing(PublicKey)
     * @see Unseal
     */
    public static class Seal {
        private final PublicKey recipientKey;
        private final byte[] encodedKey;

        Seal(PublicKey recipientKey) {
            this.recipientKey = recipientKey;
            encodedKey = recipientKey.getEncoded();
        }

        /**
         * Encrypts the given slice of input data into a sealed box in the provided output array at the given offset.
         *
         * @param input     array of bytes to read data to encrypt
         * @param inOffset  where in the input array to begin reading data
         * @param inLength  how many bytes to read and encrypt
         * @param output    array of bytes to write encrypted data to
         * @param outOffset where in the output array to begin writing data
         * @throws IllegalArgumentException       if the output buffer is too small
         * @throws ArrayIndexOutOfBoundsException if the offsets or length are out of bounds of the given arrays
         * @throws NullPointerException           if the input or output arrays are null
         */
        public void seal(byte[] input, int inOffset, int inLength, byte[] output, int outOffset) {
            Objects.requireNonNull(input);
            Objects.requireNonNull(output);
            if (inOffset < 0 || inOffset > input.length || inLength < 0 || outOffset < 0 || outOffset > output.length) {
                throw new ArrayIndexOutOfBoundsException();
            }
            int keyLength = encodedKey.length;
            if (output.length - outOffset < 1 + keyLength + inLength + TAG_LENGTH) {
                throw new IllegalArgumentException("Output buffer too short");
            }

            KeyPair sealKeyPair = generateKeyPair();
            JCryptoBox box = boxing(sealKeyPair, recipientKey);
            byte[] sealKey = sealKeyPair.getPublic().getEncoded();
            output[outOffset] = (byte) keyLength;
            System.arraycopy(sealKey, 0, output, outOffset + 1, keyLength);

            MessageDigest digest = SecurityLevel.getDefault().getMessageDigest();
            digest.update(sealKey);
            digest.update(encodedKey);
            byte[] nonce = digest.digest();

            box.box(nonce, input, inOffset, inLength, output, outOffset + 1 + keyLength);
        }

        /**
         * Encrypts the given slice of input data and returns the sealed box data.
         *
         * @param message array of bytes to read data to encrypt
         * @param offset  where in the message array to begin reading data to encrypt
         * @param length  how many bytes to read and encrypt
         * @return the sealed box data
         * @throws NullPointerException if the given array is null
         */
        public byte[] seal(byte[] message, int offset, int length) {
            Objects.requireNonNull(message);
            byte[] box = new byte[1 + length + encodedKey.length + TAG_LENGTH];
            seal(message, offset, length, box, 0);
            return box;
        }

        /**
         * Encrypts the given message bytes and returns the sealed box data.
         *
         * @param message array of bytes to read and encrypt
         * @return the sealed box data
         * @throws NullPointerException if the given array is null
         */
        public byte[] seal(byte[] message) {
            Objects.requireNonNull(message);
            return seal(message, 0, message.length);
        }

    }

    /**
     * Provides functionality to unseal a {@linkplain Seal sealed box}.
     *
     * @see JCryptoBox#unsealing(KeyPair)
     * @see Seal
     */
    public static class Unseal {
        private final KeyPair recipient;
        private final byte[] encodedKey;

        Unseal(KeyPair recipient) {
            this.recipient = recipient;
            encodedKey = recipient.getPublic().getEncoded();
        }

        /**
         * Decrypts the sealed box slice of input data and writes the plaintext message to the provided output array at
         * the given offset.
         *
         * @param input     array of bytes to read sealed box data to decrypt
         * @param inOffset  where in the input array to begin reading data to decrypt
         * @param inLength  length of the sealed box in bytes (includes encoded public key and authentication tag)
         * @param output    array of bytes to write decrypted message to
         * @param outOffset where in the output array to begin writing decrypted data
         * @throws IllegalArgumentException       if the sealed box cannot be successfully decrypted or if the output
         *                                        buffer is too small
         * @throws ArrayIndexOutOfBoundsException if the offsets or length are out of range of their arrays
         * @throws NullPointerException           if the input or output arrays are null
         */
        public void unseal(byte[] input, int inOffset, int inLength, byte[] output, int outOffset) {
            Objects.requireNonNull(input);
            Objects.requireNonNull(output);
            if (inOffset < 0 || inOffset > input.length || outOffset < 0 || outOffset > output.length || inLength < 0) {
                throw new ArrayIndexOutOfBoundsException();
            }
            int keyLength = Byte.toUnsignedInt(input[inOffset]);
            int boxLength = inLength - 1 - keyLength;
            if (boxLength < TAG_LENGTH) {
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
            JCryptoBox box = opening(recipient, sealKey);

            MessageDigest digest = securityLevel.getMessageDigest();
            digest.update(input, inOffset + 1, keyLength);
            digest.update(encodedKey);
            byte[] nonce = digest.digest();

            box.open(nonce, input, inOffset + 1 + keyLength, boxLength, output, outOffset);
        }

        /**
         * Decrypts the given sealed box slice and returns the plaintext message.
         *
         * @param sealedBox array of bytes to read sealed box data to decrypt
         * @param offset    where in the array to begin reading data to decrypt
         * @param length    length of the sealed box in bytes (includes encoded public key and authentication tag)
         * @return the decrypted message
         * @throws IllegalArgumentException       if the sealed box cannot be successfully decrypted
         * @throws ArrayIndexOutOfBoundsException if the offset or length are out of range for the given array
         * @throws NullPointerException           if the given array is null
         */
        public byte[] unseal(byte[] sealedBox, int offset, int length) {
            Objects.requireNonNull(sealedBox);
            if (offset < 0 || offset > sealedBox.length || length < 0) {
                throw new ArrayIndexOutOfBoundsException();
            }
            int messageLength = length - 1 - encodedKey.length - TAG_LENGTH;
            if (messageLength < 0) {
                throw new IllegalArgumentException("Sealed box too small");
            }
            byte[] message = new byte[messageLength];
            unseal(sealedBox, offset, length, message, 0);
            return message;
        }

        /**
         * Decrypts the given sealed box and returns the plaintext message.
         *
         * @param sealedBox array of bytes containing sealed box data
         * @return the decrypted message
         * @throws IllegalArgumentException if the sealed box cannot be successfully decrypted
         * @throws NullPointerException     if the given array is null
         */
        public byte[] unseal(byte[] sealedBox) {
            Objects.requireNonNull(sealedBox);
            return unseal(sealedBox, 0, sealedBox.length);
        }
    }
}
