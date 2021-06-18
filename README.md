[![Maven Central](https://img.shields.io/maven-central/v/com.bol/cryptvault.svg)](http://search.maven.org/#search%7Cga%7C1%7Ccom.bol)
[![Build](https://github.com/bolcom/cryptvault/actions/workflows/maven.yml/badge.svg)](https://github.com/bolcom/cryptvault/actions)

# Cryptvault

Allows for a versioned, secure generic crypt/decrypt in java.

Originally developed for [spring-data-mongodb-encrypt](https://github.com/bolcom/spring-data-mongodb-encrypt), it is now offered as a general use library.

## Features

- key versioning (to help migrating to new key without need to convert data)
- uses 256-bit AES by default
- supports any encryption available in Java (via JCE)
- simple
- no dependencies

## Use

Add dependency:

```xml
        <dependency>
            <groupId>com.bol</groupId>
            <artifactId>cryptvault</artifactId>
            <version>1.0.2</version>
        </dependency>
```

And add the following to your `application.yml`:

```yaml
cryptvault:
  keys:
    - version: 1
      key: hqHKBLV83LpCqzKpf8OvutbCs+O5wX5BPu3btWpEvXA=
```

And you're done!

Example usage:

```java
    @Autowired CryptVault cryptVault;

    // encrypt
    byte[] encrypted = cryptVault.encrypt("rock".getBytes());

    // decrypt
    byte[] decrypted = cryptVault.decrypt(encrypted);
    
    new String(decrypted).equals("rock");   // true 
```

## Manual configuration

You can also configure `CryptVault` yourself. Look at [how spring autoconfig configures CryptVault](src/main/java/com/bol/config/CryptVaultAutoConfiguration.java) for details.

## Keys

This library supports AES 256 bit keys out of the box. It's possible to extend this, check the source code (`CryptVault` specifically) on how to do so.

To generate a key, you can use the following command line:

```
dd if=/dev/urandom bs=1 count=32 | base64
```

## Exchange keys

It is advisable to rotate your keys every now and then. To do so, define a new key version in `application.yml`:

```yaml
cryptvault:
  keys:
    - version: 1
      key: hqHKBLV83LpCqzKpf8OvutbCs+O5wX5BPu3btWpEvXA=
    - version: 2
      key: ge2L+MA9jLA8UiUJ4z5fUoK+Lgj2yddlL6EzYIBqb1Q=
```  

`spring-data-mongodb-encrypt` would automatically use the highest versioned key for encryption by default, but supports decryption using any of the keys. This allows you to deploy a new key, and either let old data slowly get phased out, or run a nightly load+save batch job to force key migration. Once all old keys are phased out, you may remove the old key from the configuration.

You can use

```yaml
cryptvault:
  default-key: 1
```

to override which version of the defined keys is considered 'default'.


## Expected size of encrypted data

Depending on how much padding is used, you can expect 17..33 bytes for encryption overhead (salt + padding).
