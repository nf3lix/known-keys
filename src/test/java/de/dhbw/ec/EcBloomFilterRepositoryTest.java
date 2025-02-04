package de.dhbw.ec;

import io.rebloom.client.Client;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import redis.clients.jedis.JedisPool;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

import static de.dhbw.ec.EcTestUtil.ecPoint;
import static de.dhbw.ec.EcTestUtil.ecPublicKey;

@SpringBootTest
public class EcBloomFilterRepositoryTest {

    @Autowired
    private EcBloomFilterRepository ecBloomFilterRepository;

    @BeforeEach
    void setUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testUseModulusAsKeyRepresentation() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        final String xCoord = "42134508838896037615597729412571348241399061755847904145515134493259224923712";
        final ECPublicKey publicKeyStub = ecPublicKey("secp256r1", ecPoint(
                xCoord,
                "94962155699533225367980242393929424288013306610435794966719739023909263200356"
        ));
        final String keyRepresentation = ecBloomFilterRepository.getKeyRepresentation(publicKeyStub);
        assert keyRepresentation.equals(xCoord);
    }

}
