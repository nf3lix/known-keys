package de.dhbw.rsa;

import de.dhbw.cuckoo.AbstractCuckooFilterRepository;
import io.rebloom.client.Client;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;
import redis.clients.jedis.JedisPool;

import java.security.interfaces.RSAPublicKey;

import static de.dhbw.cuckoo.CuckooFilterInitializer.RSA_CUCKOO_FILTER_NAME;

@Repository
@Profile("cuckoo_filter")
public class RsaCuckooFilterRepository extends AbstractCuckooFilterRepository<RSAPublicKey> {

    public RsaCuckooFilterRepository(final Client publicKeyClient, final JedisPool jedisPool) {
        super(publicKeyClient, jedisPool, RSA_CUCKOO_FILTER_NAME);
    }

    @Override
    protected String getKeyRepresentation(final RSAPublicKey publicKey) {
        return publicKey.getModulus().toString();
    }
}
