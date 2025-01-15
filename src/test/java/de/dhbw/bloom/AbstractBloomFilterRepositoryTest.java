package de.dhbw.bloom;

import io.rebloom.client.Client;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;

import java.math.BigInteger;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;

import static de.dhbw.rsa.RsaTestUtils.rsaPublicKey;
import static org.mockito.Mockito.*;

@SpringBootTest
public class AbstractBloomFilterRepositoryTest {

    @MockitoBean
    private Client bloomFilterClient;

    @MockitoBean
    private JedisPool jedisPool;

    AbstractBloomFilterRepository<RSAPublicKey> bloomFilterRepository;

    private RSAPublicKey publicKeyStub;

    private final static String FILTER_NAME = "FILTER_NAME";

    @BeforeEach
    void setUp() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        bloomFilterRepository = new AbstractBloomFilterRepository<>(bloomFilterClient, jedisPool, FILTER_NAME) {
            @Override
            protected String getKeyRepresentation(RSAPublicKey publicKey) {
                return "KEY_REPRESENTATION";
            }
        };
        final BigInteger modulus = new BigInteger("9462127310943028450513446955298051246068106169818976319508148622091607268242929842057464753432526034171966724638379914356963896019954886942531223946184363");
        final BigInteger exponent = BigInteger.valueOf(65537);
        publicKeyStub = rsaPublicKey(modulus, exponent);
    }

    @Test
    public void testAddPublicKey() {
        bloomFilterRepository.addPublicKey(publicKeyStub);
        verify(bloomFilterClient).add(FILTER_NAME, "KEY_REPRESENTATION");
    }

    @Test
    public void testPublicKeyExistsTrue() {
        when(bloomFilterClient.exists(FILTER_NAME, "KEY_REPRESENTATION")).thenReturn(true);
        final boolean isKnown = bloomFilterRepository.isProbablyKnown(publicKeyStub);
        assert isKnown;
        verify(bloomFilterClient).exists(FILTER_NAME, "KEY_REPRESENTATION");
    }

    @Test
    public void testPublicKeyExistsFalse() {
        when(bloomFilterClient.exists(FILTER_NAME, "KEY_REPRESENTATION")).thenReturn(false);
        final boolean isKnown = bloomFilterRepository.isProbablyKnown(publicKeyStub);
        assert !isKnown;
        verify(bloomFilterClient).exists(FILTER_NAME, "KEY_REPRESENTATION");
    }

    @Test
    public void testGetMemoryConsumption() {
        final Jedis jedis = mock(Jedis.class);
        when(jedis.memoryUsage(FILTER_NAME)).thenReturn(42L);
        when(jedisPool.getResource()).thenReturn(jedis);
        final long memoryConsumption = bloomFilterRepository.getMemoryConsumption();
        assert memoryConsumption == 42L;
        verify(jedis).memoryUsage(FILTER_NAME);
    }

}
