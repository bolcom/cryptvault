package com.bol.crypt;

import java.util.Arrays;
import java.util.Base64;

public class KeyVersion {
    /**
     * The version. Can be no bigger than a byte, so only values [0, 256) are
     * acceptable.
     */
    public final int version;
    /**
     * A JCA "transformation" consisting of "algorithm/mode of
     * operation/padding". E.g. {@code "AES/CBC/PKCS5Padding"}.
     * Case-insensitive.
     */
    public final String transformation;
    /**
     * The actual key used in encryption, i.e. no key derivation is performed
     * on this key. The size depends on the algorithm used. E.g. in AES-256,
     * the key size should be 256 bits/32 bytes. An incorrect key size will
     * result in exceptions.
     */
    public final byte[] key;
    /**
     * Whether this key was used with version 1 of this library. In that case,
     * this key version can only be used for decryption. New encryptions should
     * be done with a new key.
     */
    public final boolean legacy;

    public KeyVersion(int version, String transformation, byte[] key, boolean legacy) {
        this.version = version;
        this.transformation = transformation;
        this.key = key;
        this.legacy = legacy;
    }

    public KeyVersion(int version, String transformation, byte[] key) {
        this(version, transformation, key, false);
    }

    public KeyVersion(int version, String transformation, String keyBase64, boolean legacy) {
        this(version, transformation, Base64.getDecoder().decode(keyBase64), legacy);
    }

    public KeyVersion(int version, String transformation, String keyBase64) {
        this(version, transformation, keyBase64, false);
    }

    @Override
    public String toString() {
        return "KeyVersion{" +
                "version=" + version +
                ", transformation='" + transformation + '\'' +
                ", key=" + Arrays.toString(key) +
                ", legacy=" + legacy +
                '}';
    }
}