package de.dhbw.ec;

import de.dhbw.AbstractCuckooFilterRepository;
import io.rebloom.client.Client;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.math.ec.ECPoint;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;
import redis.clients.jedis.JedisPool;

@Repository
@Profile("cuckoo_filter")
public class EcCuckooFilterRepository extends AbstractCuckooFilterRepository<ECPublicKey> {

    public EcCuckooFilterRepository(final Client publicKeyClient, final JedisPool jedisPool) {
        super(publicKeyClient, jedisPool, "ec_public_point_cuckoo_filter");
    }

    @Override
    protected String getKeyRepresentation(ECPublicKey publicKey) {
        final ECPoint publicKeyPoint = publicKey.getQ();
        return publicKeyPoint.getDetachedPoint().getXCoord().toBigInteger().toString();
    }
}
