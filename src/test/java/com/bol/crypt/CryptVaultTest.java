package com.bol.crypt;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class CryptVaultTest {
    private static final String keyBase64 = "VGltVGhlSW5jcmVkaWJsZURldmVsb3BlclNlY3JldCE=";
    private static final String plaintext = "The quick brown fox jumps over the lazy dog";
    private static final byte[] plainBytes = plaintext.getBytes(StandardCharsets.UTF_8);
    private CryptVault cryptVault;

    @BeforeEach
    public void setup() {
        var keyVersions = new KeyVersions();
        keyVersions.addVersion(new KeyVersion(1, "AES/CBC/PKCS5Padding", keyBase64, false));
        cryptVault = CryptVault.of(keyVersions);
    }

    @Test
    public void consecutiveEncryptsDifferentResults() {
        KeyVersion firstVersion = cryptVault.keyVersions.get(1).orElseThrow();
        byte[] cryptedSecret1 = cryptVault.encrypt(firstVersion, plainBytes);
        byte[] cryptedSecret2 = cryptVault.encrypt(firstVersion, plainBytes);

        assertThat(cryptedSecret1.length).isEqualTo(cryptedSecret2.length);
        // version
        assertThat(cryptedSecret1[0]).isEqualTo(cryptedSecret2[0]);

        // chances of having the same bytes in the same positions is negligible
        int equals = 0;
        for (int i = 1; i < cryptedSecret1.length; i++) {
            if (cryptedSecret1[i] == cryptedSecret2[i]) equals++;
        }

        assertThat(equals).withFailMessage("crypted fields look too much alike")
                .isLessThanOrEqualTo(cryptedSecret1.length / 10);
    }

    @Test
    public void decryptionUndoesEncryption() {
        byte[] encryptedBytes = cryptVault.encrypt(plainBytes);
        byte[] decryptedBytes = cryptVault.decrypt(encryptedBytes);
        String decryptedString = new String(decryptedBytes, StandardCharsets.UTF_8);

        assertThat(decryptedString).isEqualTo(plaintext);
    }

    @Test
    public void wrongKeyDecryptionFailure() {
        byte[] encryptedBytes = cryptVault.encrypt(plainBytes);

        byte[] otherKeyBytes = Base64.getDecoder().decode("VGhpcyBpcyB0aGUgd3Jvbmcga2V5LCBJJ20gc29ycnk=");
        var otherKeyVersions = new KeyVersions();
        otherKeyVersions.addVersion(new KeyVersion(1, "AES/CBC/PKCS5Padding", otherKeyBytes));
        CryptVault otherVault = CryptVault.of(otherKeyVersions);

        assertThrows(CryptOperationException.class, () -> otherVault.decrypt(encryptedBytes));
    }

    @Test
    public void missingKeyVersionsDecryptionFailure() {
        byte[] encryptedBytes = cryptVault.encrypt(plainBytes);
        encryptedBytes[1] = (byte) 2;

        assertThrows(CryptOperationException.class, () -> cryptVault.decrypt(encryptedBytes));
    }

    @Test
    public void highestKeyVersionIsDefaultKey() {
        byte[] encryptedBytes = cryptVault.encrypt(plainBytes);

        var secondKeyVersion = new KeyVersion(
                2,
                "AES/CBC/PKCS5Padding",
                Base64.getDecoder().decode("IqWTpi549pJDZ1kuc9HppcMxtPfu2SP6Idlh+tz4LL4=")
        );
        cryptVault.keyVersions.addVersion(secondKeyVersion);
        byte[] encryptedBytes2 = cryptVault.encrypt(plainBytes);

        assertThat(encryptedBytes[1]).isEqualTo((byte) 1);
        assertThat(encryptedBytes2[1]).isEqualTo((byte) 2);
    }

    @Test
    public void keyVersionIsDerivedFromEncryptedBlob() {
        var firstKeyVersion = cryptVault.keyVersions.get(1).orElseThrow();
        var secondKeyVersion = new KeyVersion(
                2,
                "ChaCha20-Poly1305",
                Base64.getDecoder().decode("IqWTpi549pJDZ1kuc9HppcMxtPfu2SP6Idlh+tz4LL4="));
        cryptVault.keyVersions.addVersion(secondKeyVersion);

        byte[] encryptedUnderFirstKeyBytes = cryptVault.encrypt(firstKeyVersion, plainBytes);
        byte[] encryptedUnderSecondKeyBytes = cryptVault.encrypt(secondKeyVersion, plainBytes);

        assertThat(encryptedUnderFirstKeyBytes[1]).isEqualTo((byte) 1);
        assertThat(encryptedUnderSecondKeyBytes[1]).isEqualTo((byte) 2);

        assertThat(cryptVault.decrypt(encryptedUnderFirstKeyBytes)).isEqualTo(plainBytes);
        assertThat(cryptVault.decrypt(encryptedUnderSecondKeyBytes)).isEqualTo(plainBytes);
    }

    @Test
    public void differentKeyVersionsShouldLiveSideBySide() {
        byte[] aesKey = "2~_J2#Kb=_xV3!wMmX3}LAny0fie7:hT".getBytes(StandardCharsets.UTF_8);
        var aes256CtrTransformation = "AES/CTR/NoPadding";
        var aes256CtrVersion = new KeyVersion(1, aes256CtrTransformation, aesKey);

        var desKey = "jcs&@IwY".getBytes();
        var desCbcTransformation = "DES/CBC/PKCS5Padding";
        var desCbcVersion = new KeyVersion(2, desCbcTransformation, desKey);

        var cryptVault = CryptVault.of(KeyVersions.of(aes256CtrVersion, desCbcVersion));

        byte[] aes256CtrBlob = cryptVault.encrypt(aes256CtrVersion, plainBytes);
        assertThat(aes256CtrBlob[1]).isEqualTo((byte) 1);
        assertThat(aes256CtrBlob.length).isEqualTo(1 + 1 + 1 + aes256CtrBlob[2] + plaintext.length());

        byte[] chacha20Poly1305Blob = cryptVault.encrypt(desCbcVersion, plainBytes);
        assertThat(chacha20Poly1305Blob[1]).isEqualTo((byte) 2);
        int paddingLength = plaintext.length() % 16 == 0 ? 16 : 16 - plaintext.length() % 16;
        assertThat(chacha20Poly1305Blob.length).isEqualTo(1 + 1 + 1 + chacha20Poly1305Blob[2] + plaintext.length() + paddingLength);
    }

    @Test
    public void ecbWithoutIv() {
        byte[] key = "2~_J2#Kb=_xV3!wMmX3}LAny0fie7:hT".getBytes(StandardCharsets.UTF_8);

        String aes256EcbTransformation = "AES/ECB/PKCS5Padding";
        var aes256EcbVersion = new KeyVersion(1, aes256EcbTransformation, key);
        var cryptVersions = KeyVersions.of(aes256EcbVersion);
        var vault = CryptVault.of(cryptVersions);

        byte[] ciphertext = vault.encrypt(plainBytes);
        String decryptedText = new String(vault.decrypt(ciphertext));

        assertThat(decryptedText).isEqualTo(plaintext);
    }

    @Test
    public void gcmWithSameIvEveryTime() {
        byte[] key = "2~_J2#Kb=_xV3!wMmX3}LAny0fie7:hT".getBytes(StandardCharsets.UTF_8);

        var aes256GcmTransformation = "AES/GCM/NoPadding";
        var aes256GcmVersion = new KeyVersion(1, aes256GcmTransformation, key);
        var keyVersions = KeyVersions.of(aes256GcmVersion);
        var cryptVault = CryptVault.of(keyVersions);

        byte[] reusedIv = new byte[16];
        new SecureRandom().nextBytes(reusedIv);

        var algoParamSpec = new GCMParameterSpec(128, reusedIv);

        byte[] firstEncryptedBlob = cryptVault.encrypt(aes256GcmVersion, plainBytes, algoParamSpec);
        assertThat(firstEncryptedBlob[1]).isEqualTo((byte) 1);
        assertThat(Arrays.copyOfRange(firstEncryptedBlob, 3, 3 + firstEncryptedBlob[2])).contains(reusedIv);

        byte[] secondEncryptedBlob = cryptVault.encrypt(aes256GcmVersion, plainBytes, algoParamSpec);
        assertThat(secondEncryptedBlob[1]).isEqualTo((byte) 1);
        assertThat(Arrays.copyOfRange(secondEncryptedBlob, 1, 3 + secondEncryptedBlob[2])).contains(reusedIv);

        assertThat(new String(cryptVault.decrypt(firstEncryptedBlob))).isEqualTo(plaintext);
        assertThat(new String(cryptVault.decrypt(secondEncryptedBlob))).isEqualTo(plaintext);
    }
}
