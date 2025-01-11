package de.dhbw.rsa;

import de.dhbw.PublicKeyRepository;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.math.BigInteger;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;

import static de.dhbw.rsa.RsaTestUtils.rsaPublicKey;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SpringBootTest
public class RsaPublicKeyServiceTest {

    @MockitoBean
    PublicKeyRepository<RSAPublicKey> rsaPublicKeyPublicKeyRepository;

    @Autowired
    RsaPublicKeyService rsaPublicKeyService;

    RSAPublicKey publicKeyStub;

    @BeforeEach
    void setUp() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        final BigInteger modulus = new BigInteger("9462127310943028450513446955298051246068106169818976319508148622091607268242929842057464753432526034171966724638379914356963896019954886942531223946184363");
        final BigInteger exponent = BigInteger.valueOf(65537);
        publicKeyStub = rsaPublicKey(modulus, exponent);
    }

    @Test
    public void testAddPublicKey() {
        rsaPublicKeyService.addPublicKey(publicKeyStub);
        verify(rsaPublicKeyPublicKeyRepository).addPublicKey(publicKeyStub);
    }

    @Test
    public void testIsKnownTrue() {
        when(rsaPublicKeyPublicKeyRepository.isProbablyKnown(publicKeyStub)).thenReturn(true);
        final boolean isKnown = rsaPublicKeyService.isProbablyKnown(publicKeyStub);
        assert isKnown;
        verify(rsaPublicKeyPublicKeyRepository).isProbablyKnown(publicKeyStub);
    }

    @Test
    public void testIsKnownFalse() {
        when(rsaPublicKeyPublicKeyRepository.isProbablyKnown(publicKeyStub)).thenReturn(false);
        final boolean isKnown = rsaPublicKeyService.isProbablyKnown(publicKeyStub);
        assert !isKnown;
        verify(rsaPublicKeyPublicKeyRepository).isProbablyKnown(publicKeyStub);
    }

    @Test
    public void testGetMemoryConsumption() {
        when(rsaPublicKeyPublicKeyRepository.getMemoryConsumption()).thenReturn(42L);
        final long memoryConsumption = rsaPublicKeyService.getMemoryConsumption();
        assert memoryConsumption == 42L;
        verify(rsaPublicKeyPublicKeyRepository).getMemoryConsumption();
    }

}
