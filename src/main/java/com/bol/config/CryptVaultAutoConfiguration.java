package com.bol.config;

import com.bol.crypt.CryptVault;
import com.bol.crypt.KeyVersion;
import com.bol.crypt.KeyVersions;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import java.util.List;
import java.util.Objects;

@AutoConfiguration
@ConditionalOnProperty("cryptvault.keys[0].key")
@EnableConfigurationProperties(value = {CryptVaultAutoConfiguration.CryptVaultConfigurationProperties.class})
public class CryptVaultAutoConfiguration {

    @Bean
    CryptVault cryptVault(CryptVaultConfigurationProperties properties) {
        if (properties.keys == null || properties.keys.isEmpty()) {
            throw new IllegalStateException("property 'keys' is not set");
        }

        KeyVersions versions = new KeyVersions();
        for (KeyVersionProperties props : properties.keys) {
            Objects.requireNonNull(props.key, String.format("key version %d has a null key", props.version));
            if (props.version < 1 || props.version > 255) {
                throw new IllegalArgumentException(String.format("version should be [1, 255], got %d", props.version));
            }
            if (props.transformation == null) props.transformation = "AES/CBC/PKCS5Padding";
            versions.addVersion(new KeyVersion(props.version, props.transformation, props.key, props.legacy));
        }

        if (properties.defaultKey != null) {
            if (properties.defaultKey < 1 || properties.defaultKey > 255) {
                var msg = String.format("default key version should be in [1, 255], was %d", properties.defaultKey);
                throw new IllegalStateException(msg);
            }
            versions.get(properties.defaultKey).ifPresentOrElse(
                    versions::setDefault,
                    () -> {
                        var msg = String.format("no version %d registered; cannot make default", properties.defaultKey);
                        throw new IllegalStateException(msg);
                    });
        }

        return CryptVault.of(versions);
    }

    @ConfigurationProperties("cryptvault")
    public static class CryptVaultConfigurationProperties {
        List<KeyVersionProperties> keys;
        Integer defaultKey;

        public void setKeys(List<KeyVersionProperties> keys) {
            this.keys = keys;
        }

        public void setDefaultKey(Integer defaultKey) {
            this.defaultKey = defaultKey;
        }
    }

    public static class KeyVersionProperties {
        int version;
        String transformation;
        String key;
        boolean legacy;

        public void setVersion(int version) {
            this.version = version;
        }

        public void setTransformation(String transformation) {
            this.transformation = transformation;
        }

        public void setKey(String key) {
            this.key = key;
        }

        public void setLegacy(boolean legacy) {
            this.legacy = legacy;
        }

        @Override
        public String toString() {
            return "KeyVersionProperties{" +
                    "version=" + version +
                    ", transformation='" + transformation + '\'' +
                    ", keyBase64='" + key + '\'' +
                    '}';
        }
    }
}
