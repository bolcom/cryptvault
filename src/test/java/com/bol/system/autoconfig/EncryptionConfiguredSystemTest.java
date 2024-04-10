package com.bol.system.autoconfig;

import com.bol.config.CryptVaultAutoConfiguration;
import com.bol.crypt.CryptOperationException;
import com.bol.crypt.CryptVault;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ActiveProfiles("autoconfig")
@EnableAutoConfiguration
@SpringBootTest(classes = {EncryptionConfiguredSystemTest.class, CryptVaultAutoConfiguration.class})
public class EncryptionConfiguredSystemTest {
    private static final byte[] cleartext = ("Lorem ipsum dolor sit amet, " +
            "consectetur adipiscing elit, sed do eiusmod tempor incididunt ut " +
            "labore et dolore magna aliqua.").getBytes();

    @Autowired(required = false)
    CryptVault cryptVault;

    @Test
    public void sanityTest() {
        assertThat(cryptVault).isNotNull();
        assertThat(cryptVault.keyVersions.size()).isEqualTo(6);
    }

    @Test
    public void specifyCipherInExternalConfig() {
        var secondKeyVersion = cryptVault.keyVersions.get(2).orElseThrow();
        byte[] encryptedBlob = cryptVault.encrypt(secondKeyVersion, cleartext);

        // version + len(cleartext) w/o padding
        assertThat(encryptedBlob.length).isEqualTo(1 + 1 + 1 + encryptedBlob[2] + cleartext.length);
    }

    @Test
    public void legacyKeyVersionShouldThrowWhenUsedForNewEncryption() {
        // CryptVault 1 did not specify a CryptVault protocol version in the encrypted blob
        var legacyVersion = cryptVault.keyVersions.get(1).orElseThrow();
        var t = assertThrows(
                CryptOperationException.class,
                () -> cryptVault.encrypt(legacyVersion, cleartext)
        );

        assertThat(t.getMessage()).startsWith("cannot encrypt with legacy key version");
    }

    @Test
    public void legacyKeyVersionShouldBeAbleToDecryptLegacyEncryption() {
        var legacyBlob = Base64.getDecoder().decode("gV4dQBm9mYJ1JC3DDs7Wj4cdbJKJALhIPktD4AT2sq4/");
        // in legacy version, 0x80 (-128) was version 0, 0x81 (-127) was version 1, etc.
        assertThat(legacyBlob[0]).isEqualTo((byte) 0x81);
        byte[] recoveredCleartextAsBytes = cryptVault.decrypt(legacyBlob);
        assertThat(new String(recoveredCleartextAsBytes)).isEqualTo("lorem ipsum");
    }

    @Test
    public void blobNotMarkedAsLegacyShouldFailDecryption() {
        var legacyBlob = Base64.getDecoder().decode("gl4dQBm9mYJ1JC3DDs7Wj4cdbJKJALhIPktD4AT2sq4/");
        assertThat(legacyBlob[0]).isEqualTo((byte) 0x82);
        var t = assertThrows(CryptOperationException.class, () -> cryptVault.decrypt(legacyBlob));
        assertThat(t.getMessage()).startsWith("cryptvault protocol version in encrypted blob is unknown:");
    }

    @Test
    public void noTransformationSpecifiedShouldFallBackToAesCbcPkcs5Padding() {
        var keyVersionWithoutTransformation = cryptVault.keyVersions.get(6).orElseThrow();
        byte[] recoveredCleartext = cryptVault.decrypt(cryptVault.encrypt(keyVersionWithoutTransformation, cleartext));
        assertThat(recoveredCleartext).isEqualTo(cleartext);
    }
}
