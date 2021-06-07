package com.bol.crypt;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
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
                .with256BitAesCbcPkcs5PaddingAnd128BitSaltKey(1, secretKeyBytes);
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
                .with256BitAesCbcPkcs5PaddingAnd128BitSaltKey(1, keyBytes);

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

        cryptVault.with256BitAesCbcPkcs5PaddingAnd128BitSaltKey(2, Base64.getDecoder().decode("IqWTpi549pJDZ1kuc9HppcMxtPfu2SP6Idlh+tz4LL4="));
        byte[] encryptedBytes2 = cryptVault.encrypt(plainBytes);

        assertThat(fromSignedByte(encryptedBytes[0])).isEqualTo(1);
        assertThat(fromSignedByte(encryptedBytes2[0])).isEqualTo(2);
    }

    @Test
    public void keyVersionIsDerivedFromCipher() {
        cryptVault.with256BitAesCbcPkcs5PaddingAnd128BitSaltKey(2, Base64.getDecoder().decode("IqWTpi549pJDZ1kuc9HppcMxtPfu2SP6Idlh+tz4LL4="));

        byte[] encryptedBytes = cryptVault.encrypt(1, plainBytes);

        byte[] encryptedBytes2 = cryptVault.encrypt(2, plainBytes);

        assertThat(fromSignedByte(encryptedBytes[0])).isEqualTo(1);
        assertThat(fromSignedByte(encryptedBytes2[0])).isEqualTo(2);

        assertThat(cryptVault.decrypt(encryptedBytes)).isEqualTo(plainBytes);
        assertThat(cryptVault.decrypt(encryptedBytes2)).isEqualTo(plainBytes);
    }
}
