package de.dhbw.rsa;

import de.dhbw.AbstractHashSetRepository;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;
import redis.clients.jedis.JedisPool;

import java.security.interfaces.RSAPublicKey;

@Repository
@Profile("set")
public class RsaHashSetRepository extends AbstractHashSetRepository<RSAPublicKey> {

    public RsaHashSetRepository(final JedisPool jedisPool) {
        super(jedisPool, "rsa_modulus_set");
    }

    @Override
    protected String getKeyRepresentation(final RSAPublicKey publicKey) {
        return publicKey.getModulus().toString();
    }

}
