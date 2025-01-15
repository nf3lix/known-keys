package de.dhbw.cuckoo;

import de.dhbw.PublicKeyRepository;
import io.rebloom.client.Client;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;

import java.security.PublicKey;

public abstract class AbstractCuckooFilterRepository<T extends PublicKey> implements PublicKeyRepository<T> {

    private final Client publicKeyClient;
    private final JedisPool jedisPool;
    private final String cuckooFilterName;

    public AbstractCuckooFilterRepository(final Client publicKeyClient, final JedisPool jedisPool, final String cuckooFilterName) {
        this.publicKeyClient = publicKeyClient;
        this.jedisPool = jedisPool;
        this.cuckooFilterName = cuckooFilterName;
    }

    protected abstract String getKeyRepresentation(T publicKey);

    @Override
    public void addPublicKey(final T publicKey) {
        publicKeyClient.cfAdd(cuckooFilterName, getKeyRepresentation(publicKey));
    }

    @Override
    public boolean isProbablyKnown(final T publicKey) {
        return publicKeyClient.cfExists(cuckooFilterName, getKeyRepresentation(publicKey));
    }

    @Override
    public long getMemoryConsumption() {
        try (final Jedis jedis = jedisPool.getResource()) {
            return jedis.memoryUsage(cuckooFilterName);
        }
    }

}
