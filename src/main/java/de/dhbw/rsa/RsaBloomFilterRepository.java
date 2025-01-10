package de.dhbw.rsa;

import de.dhbw.JedisConfig;
import de.dhbw.PublicKeyRepository;
import io.rebloom.client.Client;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;

import java.security.interfaces.RSAPublicKey;

@Repository
@Profile({"bloom_filter", "default"})
public class RsaBloomFilterRepository implements PublicKeyRepository<RSAPublicKey> {

    private final Client publicKeyClient;
    private final JedisPool jedisPool;

    public RsaBloomFilterRepository(final Client publicKeyClient, final JedisPool jedisPool) {
        this.publicKeyClient = publicKeyClient;
        this.jedisPool = jedisPool;
    }

    @Override
    public void addPublicKey(final RSAPublicKey publicKey) {
        publicKeyClient.add(JedisConfig.RSA_BLOOM_FILTER_NAME, publicKey.getModulus().toString());
    }

    @Override
    public boolean isProbablyKnown(final RSAPublicKey publicKey) {
        return publicKeyClient.exists(JedisConfig.RSA_BLOOM_FILTER_NAME, publicKey.getModulus().toString());
    }

    @Override
    public long getMemoryConsumption() {
        try (final Jedis jedis = jedisPool.getResource()) {
            return jedis.memoryUsage(JedisConfig.RSA_BLOOM_FILTER_NAME);
        }
    }
}
