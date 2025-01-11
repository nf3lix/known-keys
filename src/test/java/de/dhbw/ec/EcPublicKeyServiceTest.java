package de.dhbw.ec;

import de.dhbw.PublicKeyRepository;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

import static de.dhbw.ec.EcTestUtil.ecPoint;
import static de.dhbw.ec.EcTestUtil.ecPublicKey;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SpringBootTest
public class EcPublicKeyServiceTest {

    @MockitoBean
    PublicKeyRepository<ECPublicKey> ecPublicKeyPublicKeyRepository;

    @Autowired
    EcPublicKeyService ecPublicKeyService;

    ECPublicKey publicKeyStub;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
        final String xCoord = "42134508838896037615597729412571348241399061755847904145515134493259224923712";
        publicKeyStub = ecPublicKey("secp256r1", ecPoint(
                xCoord,
                "94962155699533225367980242393929424288013306610435794966719739023909263200356"
        ));
    }

    @Test
    public void testAddPublicKey() {
        ecPublicKeyService.addPublicKey(publicKeyStub);
        verify(ecPublicKeyPublicKeyRepository).addPublicKey(publicKeyStub);
    }

    @Test
    public void testIsKnownTrue() {
        when(ecPublicKeyPublicKeyRepository.isProbablyKnown(publicKeyStub)).thenReturn(true);
        final boolean isKnown = ecPublicKeyService.isProbablyKnown(publicKeyStub);
        assert isKnown;
        verify(ecPublicKeyPublicKeyRepository).isProbablyKnown(publicKeyStub);
    }

    @Test
    public void testIsKnownFalse() {
        when(ecPublicKeyPublicKeyRepository.isProbablyKnown(publicKeyStub)).thenReturn(false);
        final boolean isKnown = ecPublicKeyService.isProbablyKnown(publicKeyStub);
        assert !isKnown;
        verify(ecPublicKeyPublicKeyRepository).isProbablyKnown(publicKeyStub);
    }

    @Test
    public void testGetMemoryConsumption() {
        when(ecPublicKeyPublicKeyRepository.getMemoryConsumption()).thenReturn(42L);
        final long memoryConsumption = ecPublicKeyService.getMemoryConsumption();
        assert memoryConsumption == 42L;
        verify(ecPublicKeyPublicKeyRepository).getMemoryConsumption();
    }

}
