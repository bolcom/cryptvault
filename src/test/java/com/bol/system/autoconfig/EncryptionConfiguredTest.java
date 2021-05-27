package com.bol.system.autoconfig;

import com.bol.config.CryptVaultAutoConfiguration;
import com.bol.crypt.CryptVault;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

import static org.assertj.core.api.Assertions.assertThat;

@ActiveProfiles("autoconfig")
@RunWith(SpringRunner.class)
@EnableAutoConfiguration
@SpringBootTest(classes = {EncryptionConfiguredTest.class, CryptVaultAutoConfiguration.class})
public class EncryptionConfiguredTest {

    @Autowired(required = false) CryptVault cryptVault;

    @Test
    public void sanityTest() {
        assertThat(cryptVault).isNotNull();
        assertThat(cryptVault.size()).isEqualTo(1);
    }
}
