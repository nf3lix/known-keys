package de.dhbw.rsa;

import de.dhbw.AbstractBloomFilterRepository;
import io.rebloom.client.Client;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;
import redis.clients.jedis.JedisPool;

import java.security.interfaces.RSAPublicKey;

import static de.dhbw.BloomFilterInitializer.RSA_BLOOM_FILTER_NAME;

@Repository
@Profile({"bloom_filter", "default"})
public class RsaBloomFilterRepository extends AbstractBloomFilterRepository<RSAPublicKey> {

    public RsaBloomFilterRepository(final Client publicKeyClient, final JedisPool jedisPool) {
        super(publicKeyClient, jedisPool, RSA_BLOOM_FILTER_NAME);
    }

    @Override
    protected String getKeyRepresentation(final RSAPublicKey publicKey) {
        return publicKey.getModulus().toString();
    }

}
