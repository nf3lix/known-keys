package de.dhbw;

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
public class AbstractHashSetRepositoryTest {

    @MockitoBean
    private JedisPool jedisPool;

    @MockitoBean
    private Jedis jedis;

    AbstractHashSetRepository<RSAPublicKey> hashSetRepository;

    private RSAPublicKey publicKeyStub;

    private final static String FILTER_NAME = "SET_NAME";

    @BeforeEach
    void setUp() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        hashSetRepository = new AbstractHashSetRepository<>(jedisPool, FILTER_NAME) {
            @Override
            protected String getKeyRepresentation(RSAPublicKey publicKey) {
                return "KEY_REPRESENTATION";
            }
        };
        final BigInteger modulus = new BigInteger("9462127310943028450513446955298051246068106169818976319508148622091607268242929842057464753432526034171966724638379914356963896019954886942531223946184363");
        final BigInteger exponent = BigInteger.valueOf(65537);
        publicKeyStub = rsaPublicKey(modulus, exponent);
        when(jedisPool.getResource()).thenReturn(jedis);
    }

    @Test
    public void testAddPublicKey() {
        hashSetRepository.addPublicKey(publicKeyStub);
        verify(jedis).sadd(FILTER_NAME, "KEY_REPRESENTATION");
    }

    @Test
    public void testPublicKeyExistsTrue() {
        when(jedis.sismember(FILTER_NAME, "KEY_REPRESENTATION")).thenReturn(true);
        final boolean isKnown = hashSetRepository.isProbablyKnown(publicKeyStub);
        assert isKnown;
        verify(jedis).sismember(FILTER_NAME, "KEY_REPRESENTATION");
    }

    @Test
    public void testPublicKeyExistsFalse() {
        when(jedis.sismember(FILTER_NAME, "KEY_REPRESENTATION")).thenReturn(false);
        final boolean isKnown = hashSetRepository.isProbablyKnown(publicKeyStub);
        assert !isKnown;
        verify(jedis).sismember(FILTER_NAME, "KEY_REPRESENTATION");
    }

    @Test
    public void testGetMemoryConsumption() {
        when(jedis.memoryUsage(FILTER_NAME)).thenReturn(42L);
        final long memoryConsumption = hashSetRepository.getMemoryConsumption();
        assert memoryConsumption == 42L;
        verify(jedis).memoryUsage(FILTER_NAME);
    }

}
