package de.dhbw;

import io.rebloom.client.Client;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;

import java.security.PublicKey;

public abstract class AbstractBloomFilterRepository<T extends PublicKey> implements PublicKeyRepository<T> {

    private final Client publicKeyClient;
    private final JedisPool jedisPool;
    private final String bloomFilterName;

    public AbstractBloomFilterRepository(final Client publicKeyClient, final JedisPool jedisPool, final String bloomFilterName) {
        this.publicKeyClient = publicKeyClient;
        this.jedisPool = jedisPool;
        this.bloomFilterName = bloomFilterName;
    }

    protected abstract String getKeyRepresentation(T publicKey);

    @Override
    public void addPublicKey(final T publicKey) {
        publicKeyClient.add(bloomFilterName, getKeyRepresentation(publicKey));
    }

    @Override
    public boolean isProbablyKnown(final T publicKey) {
        return publicKeyClient.exists(bloomFilterName, getKeyRepresentation(publicKey));
    }

    @Override
    public long getMemoryConsumption() {
        try (final Jedis jedis = jedisPool.getResource()) {
            return jedis.memoryUsage(bloomFilterName);
        }
    }

}
