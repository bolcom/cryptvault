package com.bol.crypt;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Arrays;
import java.util.Base64;

import static com.bol.crypt.CryptVault.fromSignedByte;
import static com.bol.crypt.CryptVault.toSignedByte;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class CryptVaultTest {
    private static final byte[] KEY = "VGltVGhlSW5jcmVkaWJsZURldmVsb3BlclNlY3JldCE=".getBytes();
    private static final String plainText = "The quick brown fox jumps over the lazy dog";
    private static final byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);
    private CryptVault cryptVault;

    @BeforeEach
    public void setup() {
        byte[] secretKeyBytes = Base64.getDecoder().decode(KEY);
        cryptVault = new CryptVault()
                .with256BitAesCbcPkcs5PaddingAnd16ByteIv(1, secretKeyBytes);
    }

    @Test
    public void consecutiveEncryptsDifferentResults() {
        byte[] cryptedSecret1 = cryptVault.encrypt(1, plainBytes);
        byte[] cryptedSecret2 = cryptVault.encrypt(1, plainBytes);

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

        assertThat(decryptedString).isEqualTo(plainText);
    }

    @Test
    public void wrongKeyDecryptionFailure() {
        byte[] encryptedBytes = cryptVault.encrypt(plainBytes);

        byte[] keyBytes = Base64.getDecoder().decode("VGhpcyBpcyB0aGUgd3Jvbmcga2V5LCBJJ20gc29ycnk=");
        CryptVault otherVault = new CryptVault()
                .with256BitAesCbcPkcs5PaddingAnd16ByteIv(1, keyBytes);

        assertThrows(CryptOperationException.class, () -> otherVault.decrypt(encryptedBytes));
    }

    @Test
    public void missingKeyVersionsDecryptionFailure() {
        byte[] encryptedBytes = cryptVault.encrypt(plainBytes);
        encryptedBytes[0] = toSignedByte('2');

        assertThrows(CryptOperationException.class, () -> cryptVault.decrypt(encryptedBytes));
    }

    @Test
    public void highestKeyVersionIsDefaultKey() {
        byte[] encryptedBytes = cryptVault.encrypt(plainBytes);

        cryptVault.with256BitAesCbcPkcs5PaddingAnd16ByteIv(2, Base64.getDecoder().decode("IqWTpi549pJDZ1kuc9HppcMxtPfu2SP6Idlh+tz4LL4="));
        byte[] encryptedBytes2 = cryptVault.encrypt(plainBytes);

        assertThat(fromSignedByte(encryptedBytes[0])).isEqualTo(1);
        assertThat(fromSignedByte(encryptedBytes2[0])).isEqualTo(2);
    }

    @Test
    public void keyVersionIsDerivedFromCipher() {
        cryptVault.with256BitAesCbcPkcs5PaddingAnd16ByteIv(2, Base64.getDecoder().decode("IqWTpi549pJDZ1kuc9HppcMxtPfu2SP6Idlh+tz4LL4="));

        byte[] encryptedBytes = cryptVault.encrypt(1, plainBytes);

        byte[] encryptedBytes2 = cryptVault.encrypt(2, plainBytes);

        assertThat(fromSignedByte(encryptedBytes[0])).isEqualTo(1);
        assertThat(fromSignedByte(encryptedBytes2[0])).isEqualTo(2);

        assertThat(cryptVault.decrypt(encryptedBytes)).isEqualTo(plainBytes);
        assertThat(cryptVault.decrypt(encryptedBytes2)).isEqualTo(plainBytes);
    }

    @Test
    public void differentCipherVersionsShouldLiveSideBySide() {
        byte[] key = "2~_J2#Kb=_xV3!wMmX3}LAny0fie7:hT".getBytes(StandardCharsets.UTF_8);
        String aesAlgo = "AES";
        Key keySpec = new SecretKeySpec(key, aesAlgo);

        int ivLength = 16;
        String aes256CtrCipher = "AES/CTR/NoPadding";
        CryptVersion aes256CtrVersion = new CryptVersion(1, ivLength, aes256CtrCipher, keySpec, i -> i);

        CryptVault vault = new CryptVault();
        vault.withKey(1, aes256CtrVersion);
        vault.with256BitAesCbcPkcs5PaddingAnd16ByteIv(2, key);

        String plaintext = "foo";

        byte[] aes256CtrCiphertext = vault.encrypt(1, plaintext.getBytes(StandardCharsets.UTF_8));
        assertThat(aes256CtrCiphertext[0]).isEqualTo(CryptVault.toSignedByte(1));
        assertThat(aes256CtrCiphertext.length).isEqualTo(1 + ivLength + plaintext.length());

        byte[] aes256CbcCiphertext = vault.encrypt(2, plaintext.getBytes(StandardCharsets.UTF_8));
        assertThat(aes256CbcCiphertext[0]).isEqualTo(CryptVault.toSignedByte(2));
        int paddingLength = plaintext.length() % 16 == 0 ? 16 : 16 - plaintext.length() % 16;
        assertThat(aes256CbcCiphertext.length).isEqualTo(1 + ivLength + plaintext.length() + paddingLength);
    }

    @Test
    public void ecbWithoutIv() {
        byte[] key = "2~_J2#Kb=_xV3!wMmX3}LAny0fie7:hT".getBytes(StandardCharsets.UTF_8);
        String aesAlgo = "AES";
        Key keySpec = new SecretKeySpec(key, aesAlgo);

        String aes256CtrCipher = "AES/ECB/Pkcs5Padding";
        CryptVersion aes256EcbVersion = new CryptVersion(1, 0, aes256CtrCipher, keySpec, i -> (i | 0xf) + 1);

        CryptVault vault = new CryptVault().withKey(1, aes256EcbVersion);

        String plaintext = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor";
        byte[] ciphertext = vault.encrypt(plaintext.getBytes());
        String decryptedText = new String(vault.decrypt(ciphertext));

        assertThat(decryptedText).isEqualTo(plaintext);
    }

    @Test
    public void cbcWithSameIvEveryTime() {
        byte[] key = "2~_J2#Kb=_xV3!wMmX3}LAny0fie7:hT".getBytes(StandardCharsets.UTF_8);
        String aesAlgo = "AES";
        Key keySpec = new SecretKeySpec(key, aesAlgo);

        String aes256CtrCipher = "AES/CBC/Pkcs5Padding";
        CryptVersion aes256EcbVersion = new CryptVersion(1, 16, aes256CtrCipher, keySpec, i -> (i | 0xf) + 1);

        CryptVault vault = new CryptVault().withKey(1, aes256EcbVersion);

        String plaintext = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor";

        byte[] reusedIv = vault.randomBytes(16);

        byte[] firstCiphertext = vault.encrypt(plaintext.getBytes(), reusedIv);
        assertThat(firstCiphertext[0]).isEqualTo((byte) 0x81);
        assertThat(Arrays.copyOfRange(firstCiphertext, 1, 1 + reusedIv.length)).isEqualTo(reusedIv);

        byte[] secondCiphertext = vault.encrypt(plaintext.getBytes(), reusedIv);
        assertThat(secondCiphertext[0]).isEqualTo((byte) 0x81);
        assertThat(Arrays.copyOfRange(secondCiphertext, 1, 1 + reusedIv.length)).isEqualTo(reusedIv);

        assertThat(new String(vault.decrypt(firstCiphertext))).isEqualTo(plaintext);
        assertThat(new String(vault.decrypt(secondCiphertext))).isEqualTo(plaintext);
    }
}
