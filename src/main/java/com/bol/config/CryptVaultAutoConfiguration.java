package com.bol.config;

import com.bol.crypt.CryptVault;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.List;

@Configuration
@ConditionalOnProperty("cryptvault.keys[0].key")
public class CryptVaultAutoConfiguration {

    @Bean
    CryptVault cryptVault(CryptVaultConfigurationProperties properties) {
        CryptVault cryptVault = new CryptVault();
        if (properties.keys == null || properties.keys.isEmpty()) throw new IllegalArgumentException("property 'keys' is not set");

        for (Key key : properties.keys) {
            byte[] secretKeyBytes = Base64.getDecoder().decode(key.key);
            cryptVault.with256BitAesCbcPkcs5PaddingAnd128BitSaltKey(key.version, secretKeyBytes);
        }

        if (properties.defaultKey != null) {
            cryptVault.withDefaultKeyVersion(properties.defaultKey);
        }

        return cryptVault;
    }

    @Component
    @ConfigurationProperties("cryptvault")
    public static class CryptVaultConfigurationProperties {
        List<Key> keys;
        Integer defaultKey;

        public void setKeys(List<Key> keys) {
            this.keys = keys;
        }

        public void setDefaultKey(Integer defaultKey) {
            this.defaultKey = defaultKey;
        }
    }

    public static class Key {
        int version;
        String key;

        public void setVersion(int version) {
            this.version = version;
        }

        public void setKey(String key) {
            this.key = key;
        }
    }
}
