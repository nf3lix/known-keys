package de.dhbw.rsa;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;

import java.security.interfaces.RSAPublicKey;

@Repository
@Profile("set")
public class RsaHashSetRepository implements RsaPublicKeyRepository {

    private final JedisPool jedisPool;

    private final String RSA_SET_NAME = "rsa_modulus_set";

    public RsaHashSetRepository(final JedisPool jedisPool) {
        this.jedisPool = jedisPool;
    }

    @Override
    public void addPublicKey(final RSAPublicKey publicKey) {
        try (final Jedis jedis = jedisPool.getResource()) {
            jedis.sadd(RSA_SET_NAME, publicKey.getModulus().toString());
        }
    }

    @Override
    public boolean isProbablyKnown(final RSAPublicKey publicKey) {
        try (final Jedis jedis = jedisPool.getResource()) {
            return jedis.sismember(RSA_SET_NAME, publicKey.getModulus().toString());
        }
    }

    @Override
    public long getMemoryConsumption() {
        try (final Jedis jedis = jedisPool.getResource()) {
            return jedis.memoryUsage(RSA_SET_NAME);
        }
    }
}
