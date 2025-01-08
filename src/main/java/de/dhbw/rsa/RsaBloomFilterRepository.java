package de.dhbw.rsa;

import de.dhbw.JedisConfig;
import io.rebloom.client.Client;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Repository;

import java.security.interfaces.RSAPublicKey;

@Repository
@Profile({"bloom_filter", "default"})
public class RsaBloomFilterRepository implements RsaPublicKeyRepository {

    private final Client publicKeyClient;

    public RsaBloomFilterRepository(final Client publicKeyClient) {
        this.publicKeyClient = publicKeyClient;
    }

    @Override
    public void addPublicKey(final RSAPublicKey publicKey) {
        publicKeyClient.add(JedisConfig.RSA_BLOOM_FILTER_NAME, publicKey.getModulus().toString());
    }

    @Override
    public boolean isProbablyKnown(final RSAPublicKey publicKey) {
        return publicKeyClient.exists(JedisConfig.RSA_BLOOM_FILTER_NAME, publicKey.getModulus().toString());
    }
}
