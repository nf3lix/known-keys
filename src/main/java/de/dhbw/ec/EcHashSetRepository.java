package de.dhbw.ec;

import de.dhbw.AbstractHashSetRepository;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.math.ec.ECPoint;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;
import redis.clients.jedis.JedisPool;

@Repository
@Profile("set")
public class EcHashSetRepository extends AbstractHashSetRepository<ECPublicKey> {

    public EcHashSetRepository(final JedisPool jedisPool) {
        super(jedisPool, "ec_public_point_set");
    }

    @Override
    protected String getKeyRepresentation(final ECPublicKey publicKey) {
        final ECPoint publicKeyPoint = publicKey.getQ();
        return publicKeyPoint.getDetachedPoint().getXCoord().toBigInteger().toString();
    }
}
