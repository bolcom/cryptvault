package com.bol.crypt;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

/**
 * Stores different versioned configurations containing transformations and keys.
 */
public class KeyVersions {
    private final List<KeyVersion> keyVersions = new ArrayList<>();
    private KeyVersion defaultVersion = null;

    /**
     * Creates a new instance of this class initialized with the provided key
     * versions.
     *
     * @param versions Key versions.
     * @return A new instance.
     */
    public static KeyVersions of(KeyVersion... versions) {
        var instance = new KeyVersions();
        instance.addVersions(List.of(versions));
        return instance;
    }

    /**
     * Amount of keys defined.
     */
    public int size() {
        return keyVersions.size();
    }

    /**
     * Get the key version indicated by {@code version} if it exists.
     * @param version The version. Should be [1, 255] or will throw otherwise.
     * @return The key version, if it was registered. An empty {@code Optional}
     * otherwise.
     * @throws IllegalArgumentException when version is not in [1, 255]
     */
    public Optional<KeyVersion> get(int version) {
        if (version < 1 || version > 255) throw new IllegalArgumentException("versions must be in range [1, 255]");
        return keyVersions.stream().filter((v) -> v.version == version).findFirst();
    }

    /**
     * Gets the default key version.
     * @return The default key version.
     * @throws IllegalStateException when no default key version was previously set.
     */
    public KeyVersion getDefault() {
        if (defaultVersion == null) throw new IllegalStateException("no default version set");
        return defaultVersion;
    }

    /**
     * Adds a version. If the added version has a higher version number than the
     * existing default version, the default becomes the newly-added version.
     * This is compatible with earlier versions of this library. If you want to
     * use a default version that is not the latest version, make sure to
     * invoke {@code setDefault} after calling this method.
     *
     * @param keyVersion The version to add.
     */
    public void addVersion(KeyVersion keyVersion) {
        if (keyVersion.version < 0 || keyVersion.version > 255) {
            throw new IllegalArgumentException("version must fit in a byte");
        }
        if (get(keyVersion.version).isPresent()) {
            throw new IllegalArgumentException("version " + keyVersion.version + " is already registered");
        }

        keyVersions.add(keyVersion);

        if (defaultVersion == null || keyVersion.version > defaultVersion.version) {
            defaultVersion = keyVersion;
        }
    }

    /**
     * Adds multiple versions in one swoop.
     *
     * @param versions The versions to add.
     */
    public void addVersions(Collection<KeyVersion> versions) {
        versions.forEach(this::addVersion);
    }

    /**
     * Set the default version. This is the version that is used in unqualified
     * calls to {@code CryptVault#encrypt}.
     *
     * @param defaultVersion The new default.
     */
    public void setDefault(KeyVersion defaultVersion) {
        this.defaultVersion = defaultVersion;
    }

    /**
     * Reports whether the given version number is registered as being a legacy
     * key version (< version 2 of this library). A legacy version can still be
     * decrypted if it used the default algorithm and parameters.
     * @param version A version number. It's a byte for convenience when taking
     *                it from a binary blob.
     * @return Whether {@code version} is a recognized (i.e. registered) legacy
     * key version.
     */
    public boolean isLegacyVersion(byte version) {
        // in legacy version, 0x80 (-128) was version 0, 0x81 (-127) was version 1, etc.
        var legacyVersion = (int) version - Byte.MIN_VALUE;
        return get(legacyVersion).map((kv) -> kv.legacy).orElse(false);
    }
}
