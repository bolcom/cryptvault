package com.bol.crypt;

import org.springframework.lang.Nullable;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

/**
 * The main encryptor and decryptor class.
 * <p>
 * The binary blobs produced by this library look like (numbers are bits):
 * <pre>
 * 0         8         16        24
 * +---------+---------+---------+--------------------+--------------------+
 * |proto    |key      |param    |params              |ciphertext          |
 * |version  |version  |length   |         ...        |            ...     |
 * |8        |8        |8        |[0,255]             |[16,inf)            |
 * +---------+---------+---------+--------------------+--------------------+
 */
public class CryptVault {
    /**
     * All the key versions as configured in the external configuration.
     */
    public KeyVersions keyVersions;

    private CryptVault() {
    }

    /**
     * Create a new instance initialized with the provided KeyVersions.
     *
     * @param keyVersions
     * @return A new instance.
     */
    public static CryptVault of(KeyVersions keyVersions) {
        CryptVault cryptVault = new CryptVault();
        cryptVault.keyVersions = keyVersions;
        return cryptVault;
    }

    /**
     * Encrypts the given binary blob under the transformation given by the
     * default key version. Default encryption parameters are used.
     * <p>
     * Legacy key versions are only allowed to decrypt, not encrypt.
     *
     * @param cleartext Bytes to be encrypted.
     * @return A self-contained, encrypted binary blob.
     * @throws CryptOperationException
     */
    public byte[] encrypt(byte[] cleartext) throws CryptOperationException {
        return encrypt(keyVersions.getDefault(), cleartext);
    }

    /**
     * Encrypts the given binary blob under the transformation defined in the
     * given key version. Default encryption parameters are used.
     * <p>
     * Legacy key versions are only allowed to decrypt, not encrypt.
     *
     * @param keyVersion The key version to encrypt the blob under.
     * @param cleartext  Bytes to be encrypted.
     * @return A self-contained, encrypted binary blob.
     * @throws CryptOperationException
     */
    public byte[] encrypt(KeyVersion keyVersion, byte[] cleartext) throws CryptOperationException {
        return encrypt(keyVersion, cleartext, null);
    }

    /**
     * Encrypts the given binary blob under the transformation defined in the
     * given key version. Algorithm parameters can be tweaked by passing a
     * custom {@code AlgorithmParameterSpec}.
     * <p>
     * Legacy key versions are only allowed to decrypt, not encrypt.
     *
     * @param keyVersion    The key version to encrypt the blob under.
     * @param cleartext     Bytes to be encrypted.
     * @param algoParamSpec The encryption parameters. Can be null, in which case the defaults for the given algorithm will be used.
     * @return A self-contained, encrypted binary blob.
     * @throws CryptOperationException
     */
    public byte[] encrypt(KeyVersion keyVersion, byte[] cleartext, @Nullable AlgorithmParameterSpec algoParamSpec) throws CryptOperationException {
        if (keyVersion.legacy)
            throw new CryptOperationException("cannot encrypt with legacy key version; hint: create new key version");

        try {
            Cipher cipher = Cipher.getInstance(keyVersion.transformation);

            String algorithm = keyVersion.transformation.split("/", 2)[0];
            SecretKeySpec aesKeySpec = new SecretKeySpec(keyVersion.key, algorithm);

            cipher.init(Cipher.ENCRYPT_MODE, aesKeySpec, algoParamSpec);

            byte[] ciphertext = cipher.doFinal(cleartext);

            byte[] encodedParams = (cipher.getParameters() == null) ? new byte[0] : cipher.getParameters().getEncoded();

            byte[] blob = new byte[1 + 1 + 1 + encodedParams.length + ciphertext.length];
            blob[0] = (byte) 0x0; // proto version
            blob[1] = (byte) keyVersion.version; // key version (also defines transformation)
            blob[2] = (byte) encodedParams.length; // paramLen
            System.arraycopy(encodedParams, 0, blob, 3, encodedParams.length);
            System.arraycopy(ciphertext, 0, blob, 3 + encodedParams.length, ciphertext.length);

            return blob;
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException | IOException | InvalidAlgorithmParameterException e) {
            // wrap checked exception for easy use
            throw new CryptOperationException("JCA exception caught while encrypting with key version " + keyVersion.version, e);
        }
    }

    /**
     * Decrypts a previously-encrypted, self-contained binary blob. To achieve
     * compatibility with previous versions of this library, if the first byte
     * is not a recognized protocol version (currently 00), a "legacy
     * decryption" is attempted: the blob will be decrypted according to the
     * legacy decryption process.
     *
     * @param blob The previously-encrypted binary blob.
     * @return The recovered cleartext.
     * @throws CryptOperationException
     */
    public byte[] decrypt(byte[] blob) throws CryptOperationException {
        int protoVersion = blob[0] & 0xFF;
        if (protoVersion != 0) {
            if (keyVersions.isLegacyVersion(blob[0])) {
                return attemptLegacyDecrypt(blob);
            }
            throw new CryptOperationException("cryptvault protocol version in encrypted blob is unknown: " + protoVersion);
        }

        int blobKeyVersion = blob[1] & 0xFF;
        KeyVersion keyVersion = keyVersions.get(blobKeyVersion).orElseThrow(
                () -> new CryptOperationException("key version in encrypted blob is unknown: " + blobKeyVersion));

        int paramLen = blob[2] & 0xFF;
        byte[] paramsAsBytes = new byte[paramLen];
        System.arraycopy(blob, 3, paramsAsBytes, 0, paramLen);

        try {
            Cipher decryptionCipher = Cipher.getInstance(keyVersion.transformation);

            AlgorithmParameters algoParams = decryptionCipher.getParameters();
            AlgorithmParameters storedParams = null;
            if (algoParams != null) {
                storedParams = AlgorithmParameters.getInstance(algoParams.getAlgorithm());
                storedParams.init(paramsAsBytes);
            }

            String algorithm = keyVersion.transformation.split("/", 2)[0];
            SecretKeySpec keySpec = new SecretKeySpec(keyVersion.key, algorithm);

            decryptionCipher.init(Cipher.DECRYPT_MODE, keySpec, storedParams);

            return decryptionCipher.doFinal(
                    blob, 3 + paramLen, blob.length - 3 - paramLen);
        } catch (InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException |
                 NoSuchAlgorithmException | IOException | BadPaddingException | InvalidKeyException e) {
            throw new CryptOperationException("JCA exception caught while decrypting with key version " + keyVersion.version, e);
        }
    }

    byte[] attemptLegacyDecrypt(byte[] blob) throws RuntimeException {
        int version = (int) blob[0] - Byte.MIN_VALUE;
        var legacyKeyVersion = keyVersions.get(version).orElseThrow(
                () -> new CryptOperationException(String.format("legacy version %d not registered", version))
        );

        int keyVersionLength = 1;
        int ivLength = 16;
        byte[] ivBytes = new byte[ivLength];
        System.arraycopy(blob, keyVersionLength, ivBytes, 0, ivLength);
        try {
            var ivParamSpec = new IvParameterSpec(ivBytes);

            var cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            var key = new SecretKeySpec(legacyKeyVersion.key, "AES");
            cipher.init(Cipher.DECRYPT_MODE, key, ivParamSpec);
            return cipher.doFinal(blob, keyVersionLength + ivLength, blob.length - keyVersionLength - ivLength);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException |
                 BadPaddingException | NoSuchPaddingException | NoSuchAlgorithmException e) {
            throw new CryptOperationException("JCA exception caught while attempting legacy decryption with key version " + version, e);
        }
    }
}
