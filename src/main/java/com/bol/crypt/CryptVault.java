package com.bol.crypt;

import com.bol.util.JCEPolicy;
import org.springframework.lang.Nullable;
import org.springframework.scheduling.annotation.Scheduled;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Objects;
import java.util.function.Function;

public class CryptVault {
    static final String DEFAULT_CIPHER = "AES/CBC/PKCS5Padding";
    static final String DEFAULT_ALGORITHM = "AES";
    static final int DEFAULT_IV_LENGTH = 16;

    private final CryptVersion[] cryptVersions = new CryptVersion[256];
    int defaultVersion = -1;

    /**
     * Helper method for the most used case.
     * If you even need to change this, or need backwards compatibility, use the more advanced constructor instead.
     */
    public CryptVault with256BitAesCbcPkcs5PaddingAnd16ByteIv(int version, byte[] secret) {
        if (secret.length != 32) throw new IllegalArgumentException("invalid AES key size; should be 256 bits!");

        Key key = new SecretKeySpec(secret, DEFAULT_ALGORITHM);
        CryptVersion cryptVersion = new CryptVersion(version, DEFAULT_IV_LENGTH, DEFAULT_CIPHER, key, AESLengthCalculator);
        return withKey(version, cryptVersion);
    }

    public CryptVault withKey(int version, CryptVersion cryptVersion) {
        if (version < 0 || version > 255) throw new IllegalArgumentException("version must be a byte");
        if (cryptVersions[version] != null) throw new IllegalArgumentException("version " + version + " is already defined");

        cryptVersions[version] = cryptVersion;
        if (version > defaultVersion) defaultVersion = version;
        return this;
    }

    /**
     * specifies the version used in encrypting new data. default is highest version number.
     */
    public CryptVault withDefaultKeyVersion(int defaultVersion) {
        if (defaultVersion < 0 || defaultVersion > 255) throw new IllegalArgumentException("version must be a byte");
        if (cryptVersions[defaultVersion] == null) throw new IllegalArgumentException("version " + defaultVersion + " is undefined");

        this.defaultVersion = defaultVersion;
        return this;
    }

    // FIXME: have a pool of ciphers (with locks & so), cipher init seems to be very costly (jmh it!)
    Cipher cipher(String cipher) {
        try {
            return Cipher.getInstance(cipher);
        } catch (Exception e) {
            throw new IllegalStateException("init failed for cipher " + cipher, e);
        }
    }

    private SecureRandom SECURE_RANDOM = new SecureRandom();

    // depending on securerandom implementation (that differs per platform and jvm), this might or might not be necessary.
    @Scheduled(initialDelay = 3_600_000, fixedDelay = 3_600_000)
    public void reinitSecureRandomHourly() {
        SECURE_RANDOM = new SecureRandom();
    }

    byte[] randomBytes(int numBytes) {
        byte[] bytes = new byte[numBytes];
        SECURE_RANDOM.nextBytes(bytes);
        return bytes;
    }

    public byte[] encrypt(byte[] data) {
        CryptVersion cryptVersion = cryptVersion(defaultVersion);
        if (cryptVersion.requiresIv()) {
            return encrypt(cryptVersion, data);
        } else {
            return encrypt(cryptVersion, data, null);
        }
    }

    public byte[] encrypt(int version, byte[] data) {
        return encrypt(cryptVersion(version), data);
    }

    byte[] encrypt(CryptVersion version, byte[] data) {
        return encrypt(version, data, randomBytes(version.ivLength));
    }

    public byte[] encrypt(byte[] data, @Nullable byte[] iv) {
        return encrypt(cryptVersion(defaultVersion), data, iv);
    }

    public byte[] encrypt(int version, byte[] data, @Nullable byte[] iv) {
        return encrypt(cryptVersion(version), data, iv);
    }

    byte[] encrypt(CryptVersion cryptVersion, byte[] data, @Nullable byte[] iv) {
        if (cryptVersion.requiresIv()) {
            Objects.requireNonNull(iv,
                    String.format("CryptVersion %d [cipher=%s] requires non-null IV",
                            cryptVersion.version,
                            cryptVersion.cipher)
            );
            if (cryptVersion.ivLength != iv.length) {
                throw new IllegalArgumentException(
                        String.format("CryptVersion %d [cipher=%s] requires IV of length %d, got %d",
                                cryptVersion.version,
                                cryptVersion.cipher,
                                cryptVersion.ivLength,
                                iv.length)
                );
            }
        }

        try {
            int ciphertextLength = cryptVersion.ciphertextLength.apply(data.length);
            byte[] result = new byte[1 + cryptVersion.ivLength + ciphertextLength];
            result[0] = toSignedByte(cryptVersion.version);

            IvParameterSpec ivParamSpec = null;
            if (iv != null) {
                ivParamSpec = new IvParameterSpec(iv);
                System.arraycopy(iv, 0, result, 1, cryptVersion.ivLength);
            }

            Cipher cipher = cipher(cryptVersion.cipher);
            cipher.init(Cipher.ENCRYPT_MODE, cryptVersion.key, ivParamSpec);
            cipher.doFinal(data, 0, data.length, result, cryptVersion.ivLength + 1);

            return result;
        } catch (ShortBufferException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            // wrap checked exception for easy use
            throw new CryptOperationException("JCE exception caught while encrypting with version " + cryptVersion.version, e);
        }
    }

    public byte[] decrypt(byte[] data) {
        int version = fromSignedByte(data[0]);
        CryptVersion cryptVersion = cryptVersion(version);

        try {
            IvParameterSpec ivParamSpec = null;
            if (cryptVersion.requiresIv()) {
                byte[] random = new byte[cryptVersion.ivLength];
                System.arraycopy(data, 1, random, 0, cryptVersion.ivLength);
                ivParamSpec = new IvParameterSpec(random);
            }

            Cipher cipher = cipher(cryptVersions[version].cipher);
            cipher.init(Cipher.DECRYPT_MODE, cryptVersions[version].key, ivParamSpec);
            return cipher.doFinal(data, cryptVersion.ivLength + 1, data.length - cryptVersion.ivLength - 1);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            // wrap checked exception for easy use
            throw new CryptOperationException("JCE exception caught while decrypting with key version " + version, e);
        }
    }

    public int calculateEncryptedBlobSize(int serializedLength) {
        return calculateEncryptedBlobSize(defaultVersion, serializedLength);
    }

    public int calculateEncryptedBlobSize(int version, int serializedLength) {
        CryptVersion cryptVersion = cryptVersion(version);
        return cryptVersion.ivLength + 1 + cryptVersion.ciphertextLength.apply(serializedLength);
    }

    private CryptVersion cryptVersion(int version) {
        try {
            CryptVersion result = cryptVersions[version];
            if (result == null) throw new CryptOperationException("version " + version + " undefined");
            return result;
        } catch (IndexOutOfBoundsException e) {
            if (version < 0) throw new CryptOperationException("encryption keys are not initialized");
            throw new CryptOperationException("version must be a byte (0-255)");
        }
    }

    /**
     * amount of keys defined in this CryptVault
     */
    public int size() {
        int size = 0;
        for (int i = 0; i < cryptVersions.length; i++) {
            if (cryptVersions[i] != null) size++;
        }
        return size;
    }

    /**
     * AES simply pads to 128 bits
     */
    static final Function<Integer, Integer> AESLengthCalculator = i -> (i | 0xf) + 1;

    /**
     * because, you know... java
     */
    public static byte toSignedByte(int val) {
        return (byte) (val + Byte.MIN_VALUE);
    }

    /**
     * because, you know... java
     */
    public static int fromSignedByte(byte val) {
        return ((int) val - Byte.MIN_VALUE);
    }

    static {
        // stupid JCE
        JCEPolicy.allowUnlimitedStrength();
    }
}
