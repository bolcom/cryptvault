package com.bol.crypt;

import java.security.Key;
import java.util.function.Function;

public class CryptVersion {
    public final int version;
    public final int ivLength;
    public final String cipher;
    public final Key key;
    public final Function<Integer, Integer> ciphertextLength;

    /**
     * @param version          The version number of these crypto settings. Stored in a byte, so should be [0,255].
     * @param ivLength         Length of the IV to use in bytes. For AES, if an IV is required, this should be equal to the block size (16). If 0, no IV will be used. Use this with ECB mode of operation, for example.
     * @param cipher           Name of the cipher, e.g. "AES/CTR/NoPadding".
     * @param key              The secret key.
     * @param ciphertextLength Length of the resultant ciphertext in bytes.
     */
    public CryptVersion(int version, int ivLength, String cipher, Key key, Function<Integer, Integer> ciphertextLength) {
        this.version = version;
        this.ivLength = ivLength;
        this.cipher = cipher;
        this.key = key;
        this.ciphertextLength = ciphertextLength;
    }

    public boolean requiresIv() {
        return ivLength > 0;
    }
}
