package de.dhbw.rsa;

import de.dhbw.AbstractCuckooFilterRepository;
import io.rebloom.client.Client;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;
import redis.clients.jedis.JedisPool;

import java.security.interfaces.RSAPublicKey;

@Repository
@Profile("cuckoo_filter")
public class RsaCuckooFilterRepository extends AbstractCuckooFilterRepository<RSAPublicKey> {

    public RsaCuckooFilterRepository(final Client publicKeyClient, final JedisPool jedisPool) {
        super(publicKeyClient, jedisPool, "rsa_modulus_cuckoo_filter");
    }

    @Override
    protected String getKeyRepresentation(RSAPublicKey publicKey) {
        return publicKey.getModulus().toString();
    }
}
