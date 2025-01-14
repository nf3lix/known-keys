package de.dhbw.rsa;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.math.BigInteger;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;

import static de.dhbw.rsa.RsaTestUtils.rsaPublicKey;

@SpringBootTest
@ActiveProfiles("cuckoo_filter")
public class RsaCuckooFilterRepositoryTest {

    @Autowired
    private RsaCuckooFilterRepository rsaCuckooFilterRepository;

    @BeforeEach
    void setUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testUseModulusAsKeyRepresentation() throws Exception {
        final BigInteger modulus = new BigInteger("9462127310943028450513446955298051246068106169818976319508148622091607268242929842057464753432526034171966724638379914356963896019954886942531223946184363");
        final BigInteger exponent = BigInteger.valueOf(65537);
        final RSAPublicKey publicKeyStub = rsaPublicKey(modulus, exponent);
        final String keyRepresentation = rsaCuckooFilterRepository.getKeyRepresentation(publicKeyStub);
        assert keyRepresentation.equals(modulus.toString());
    }

}
