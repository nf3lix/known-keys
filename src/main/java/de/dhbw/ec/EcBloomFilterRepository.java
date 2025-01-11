package de.dhbw.ec;

import de.dhbw.AbstractBloomFilterRepository;
import io.rebloom.client.Client;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.math.ec.ECPoint;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;
import redis.clients.jedis.JedisPool;

import static de.dhbw.BloomFilterInitializer.EC_BLOOM_FILTER_NAME;

@Repository
@Profile({"bloom_filter", "default"})
public class EcBloomFilterRepository extends AbstractBloomFilterRepository<ECPublicKey> {

    public EcBloomFilterRepository(final Client publicKeyClient, final JedisPool jedisPool) {
        super(publicKeyClient, jedisPool, EC_BLOOM_FILTER_NAME);
    }

    @Override
    protected String getKeyRepresentation(final ECPublicKey publicKey) {
        final ECPoint publicKeyPoint = publicKey.getQ();
        return publicKeyPoint.getDetachedPoint().getXCoord().toBigInteger().toString();
    }

}
