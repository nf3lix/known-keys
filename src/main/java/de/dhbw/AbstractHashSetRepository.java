package de.dhbw;

import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;

import java.security.PublicKey;

public abstract class AbstractHashSetRepository<T extends PublicKey> implements PublicKeyRepository<T> {

    protected final JedisPool jedisPool;
    private final String setName;

    protected AbstractHashSetRepository(final JedisPool jedisPool, final String setName) {
        this.jedisPool = jedisPool;
        this.setName = setName;
    }

    protected abstract String getKeyRepresentation(T publicKey);

    @Override
    public void addPublicKey(final T publicKey) {
        try (final Jedis jedis = jedisPool.getResource()) {
            jedis.sadd(setName, getKeyRepresentation(publicKey));
        }
    }

    @Override
    public boolean isProbablyKnown(final T publicKey) {
        try (final Jedis jedis = jedisPool.getResource()) {
            return jedis.sismember(setName, getKeyRepresentation(publicKey));
        }
    }

    @Override
    public long getMemoryConsumption() {
        try (final Jedis jedis = jedisPool.getResource()) {
            return jedis.memoryUsage(setName);
        }
    }

}
