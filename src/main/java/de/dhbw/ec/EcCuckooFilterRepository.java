package de.dhbw.ec;

import de.dhbw.cuckoo.AbstractCuckooFilterRepository;
import io.rebloom.client.Client;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.math.ec.ECPoint;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;
import redis.clients.jedis.JedisPool;

import static de.dhbw.cuckoo.CuckooFilterInitializer.EC_CUCKOO_FILTER_NAME;

@Repository
@Profile("cuckoo_filter")
public class EcCuckooFilterRepository extends AbstractCuckooFilterRepository<ECPublicKey> {

    public EcCuckooFilterRepository(final Client publicKeyClient, final JedisPool jedisPool) {
        super(publicKeyClient, jedisPool, EC_CUCKOO_FILTER_NAME);
    }

    @Override
    protected String getKeyRepresentation(final ECPublicKey publicKey) {
        final ECPoint publicKeyPoint = publicKey.getQ();
        return publicKeyPoint.getDetachedPoint().getXCoord().toBigInteger().toString();
    }
}
