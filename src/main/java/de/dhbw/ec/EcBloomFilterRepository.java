package de.dhbw.ec;

import de.dhbw.JedisConfig;
import io.rebloom.client.Client;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.math.ec.ECPoint;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;

@Repository
@Profile({"bloom_filter", "default"})
public class EcBloomFilterRepository implements EcPublicKeyRepository {

    private final Client publicKeyClient;
    private final JedisPool jedisPool;

    public EcBloomFilterRepository(Client publicKeyClient, JedisPool jedisPool) {
        this.publicKeyClient = publicKeyClient;
        this.jedisPool = jedisPool;
    }

    @Override
    public void addPublicKey(ECPublicKey publicKey) {
        final ECPoint publicKeyPoint = publicKey.getQ();
        final String xCoordinate = publicKeyPoint.getDetachedPoint().getXCoord().toBigInteger().toString();
        publicKeyClient.add(JedisConfig.EC_BLOOM_FILTER_NAME, xCoordinate);
    }

    @Override
    public boolean isProbablyKnown(ECPublicKey publicKey) {
        final ECPoint publicKeyPoint = publicKey.getQ();
        final String xCoordinate = publicKeyPoint.getDetachedPoint().getXCoord().toBigInteger().toString();
        return publicKeyClient.exists(JedisConfig.EC_BLOOM_FILTER_NAME, xCoordinate);
    }

    @Override
    public long getMemoryConsumption() {
        try (final Jedis jedis = jedisPool.getResource()) {
            return jedis.memoryUsage(JedisConfig.EC_BLOOM_FILTER_NAME);
        }
    }

}
