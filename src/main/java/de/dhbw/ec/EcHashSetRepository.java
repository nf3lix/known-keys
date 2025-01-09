package de.dhbw.ec;

import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.math.ec.ECPoint;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;

@Repository
@Profile("set")
public class EcHashSetRepository implements EcPublicKeyRepository {

    private final JedisPool jedisPool;
    private final String EC_SET_NAME = "ec_public_point_set";

    public EcHashSetRepository(JedisPool jedisPool) {
        this.jedisPool = jedisPool;
    }

    @Override
    public void addPublicKey(ECPublicKey publicKey) {
        final ECPoint publicKeyPoint = publicKey.getQ();
        final String xCoordinate = publicKeyPoint.getDetachedPoint().getXCoord().toBigInteger().toString();
        try (final Jedis jedis = jedisPool.getResource()) {
            jedis.sadd(EC_SET_NAME, xCoordinate);
        }
    }

    @Override
    public boolean isProbablyKnown(ECPublicKey publicKey) {
        final ECPoint publicKeyPoint = publicKey.getQ();
        final String xCoordinate = publicKeyPoint.getDetachedPoint().getXCoord().toBigInteger().toString();
        try (final Jedis jedis = jedisPool.getResource()) {
            return jedis.sismember(EC_SET_NAME, xCoordinate);
        }
    }

    @Override
    public long getMemoryConsumption() {
        try (final Jedis jedis = jedisPool.getResource()) {
            return jedis.memoryUsage(EC_SET_NAME);
        }
    }

}
