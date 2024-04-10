[![Maven Central](https://img.shields.io/maven-central/v/com.bol/cryptvault.svg)](http://search.maven.org/#search%7Cga%7C1%7Ccom.bol)
[![Build](https://github.com/bolcom/cryptvault/actions/workflows/maven.yml/badge.svg)](https://github.com/bolcom/cryptvault/actions)

# Cryptvault: versioned, secure, generic encryption/decryption in Java

> When in doubt, encrypt. When not in doubt, be in doubt.

## Features

- key versioning (to help migrating to new key without need to convert data)
- uses 256-bit AES by default
- supports any encryption available in Java (via Java Cryptography Architecture
  or JCA)
- simple
- no dependencies

## Usage

Add dependency:

```xml
<dependency>
    <groupId>com.bol</groupId>
    <artifactId>cryptvault</artifactId>
    <version>3-2.0.0</version>
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

## Keys

This library uses the encryption keys specified in the configuration directly.
Notably, it does not use any key-derivation. That means that you are responsible
for providing a key from a high-entropy source.

The length of the key depends on the algorithm specified. When using AES-256,
you need to provide a key that is 256 bits/32 bytes long. (For comparison, the
weak DES uses 64-bit keys.)

To generate a key suitable for AES-256 bit, you can use the following command:

```console
$ dd if=/dev/urandom bs=1 count=32 | base64
```

## Rotating keys

It is advisable to rotate your keys every now and then. To do so, define a new
key version in `application.yml`:

```yaml
cryptvault:
  keys:
    - version: 1
      key: hqHKBLV83LpCqzKpf8OvutbCs+O5wX5BPu3btWpEvXA=
    - version: 2
      key: ge2L+MA9jLA8UiUJ4z5fUoK+Lgj2yddlL6EzYIBqb1Q=
```  

CryptVault automatically uses the highest versioned key for encryption by
default, but supports decryption using any of the keys. This allows you to
deploy a new key, and either let old data slowly get phased out, or run a
nightly load+save batch job to force key migration. Once all old keys are phased
out, you may remove the old key from the configuration.

## Specify default key version

You can use

```yaml
cryptvault:
  default-key: 1
```

to override which version of the defined keys is considered default.

## Specify encryption algorithm

Instead of using the default AES-256 in CBC mode, you can specify the algorithm,
mode of operation and padding scheme directly in the configuration:

```yaml
cryptvault:
  keys:
    version: 1
    key: Ifw/+pLuWBjn7a1mjuToQ8hpIh8DV0WLf9b4z7iinGs=
    transformation: AES/GCM/NoPadding
```

You can use all the algorithms specified by JCA. Other valid transformations
are, for example, "DES/CTR/NoPadding" and "ChaCha20-Poly1305". For a
comprehensive list, see [Java Security Standard Algorithm Names][Java Security
Standard Algorithm Names]. 

The YAML key is called "transformation" because it signifies more than just an
algorithm, but rather a set of operations performed on an input to produce some
output. Naming it this way is consistent with JCA parlance.

## Format of the encrypted blob

The encrypted blobs look like (numbers are bits):

```
0         8         16        24
+---------+---------+---------+--------------------+--------------------+
|proto    |key      |param    |params              |ciphertext          |
|version  |version  |length   |         ...        |            ...     |
|8        |8        |8        |[0,255]             |[16,inf)            |
+---------+---------+---------+--------------------+--------------------+
```

* `proto version` is the protocol version of this blob. Having a version allows
  making improvements to this blob over time without having to decrypt all the
  old encryptions and encrypt it under a new (versionless) version.
* `key version` is the user-controlled version of the key that was used to
  encrypt the data in this blob.
* `param length` is the length of next field, the algorithm parameters 
* `params` are the algorithms parameters that that need to be known
  in order to decrypt the blob successfully. For example, when using
  AES/CBC/PKCS5Padding, this will (among some overhead) contain the 16-byte IV.
  See `java.security.AlgorithmParameters#getEncoded` for more information.
* `ciphertext` contains the output of applying the specified transformation
  under the specified key to the input.

## Expected size of encrypted data

Depending on the cipher, whether an IV or tag are used and the padding scheme
you must expect some overhead for encryption. The default cipher, AES-256-CBC
with PKCS #5 padding, requires an extra [22, 37] bytes: proto version (1) + key
version (1) + param length (1) + algorithm parameters (18) + padding (best case:
1, worst case: 16).

## Migrating from version 1 to version 2

### TL;DR: 

1. Add `legacy: true` to keys that were in use under version 1.
2. Create a new key version that will be used for new encryptions.

```yaml
cryptvault:
  keys:
    # the legacy key version (can only decrypt!)
    - version: 1
      key: yaF4Gi13Gp+gF5Tm+jMkYbQKMO3c6KYZbQmMqXQyid0=
      legacy: true
    # the new version (can encrypt/decrypt as usual)
    - version: 2
      key: CqeKXVZuDbeMk0/h1zZrBG0Mul4qMnqShaGjkxWrlQ0=
```

### More detail

Version 2 introduced a new format of the binary blob. This provides certain
benefits (see under [Format of the encrypted blob,
above](#format-of-the-encrypted-blob)). However, the old encrypted blobs have
become incompatible as a result of this breaking change. You can still decrypt
the blobs, however. Encrypting with these legacy key versions is not supported,
however. 

To migrate:

1. Add `legacy: true` to the legacy key version(s) in the config. 
2. Create a new key version that will be used for new encryptions.

Old encrypted blobs will not be updated automatically since this library does
not handle persistence. There is little harm in keeping them around as they
are still secure. However, should you wish to upgrade the stored blobs, decrypt
them and then overwrite them with a fresh encrypted version under the new key
version.

[Java Security Standard Algorithm Names]:
<https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html>
