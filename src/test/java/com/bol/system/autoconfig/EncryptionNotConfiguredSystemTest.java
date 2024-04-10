package com.bol.system.autoconfig;

import com.bol.crypt.CryptVault;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;

@EnableAutoConfiguration
@SpringBootTest(classes = EncryptionNotConfiguredSystemTest.class)
public class EncryptionNotConfiguredSystemTest {

    @Autowired(required = false)
    CryptVault cryptVault;

    @Test
    public void sanityTest() {
        assertThat(cryptVault).isNull();
    }
}
