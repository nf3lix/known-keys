package de.dhbw.rsa;

import de.dhbw.JedisConfig;
import io.rebloom.client.Client;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.interfaces.RSAPublicKey;

@Service
public class RsaPublicKeyService {

    @Autowired
    private Client publicKeyClient;

    public void addPublicKey(final RSAPublicKey publicKey) {
        publicKeyClient.add(JedisConfig.RSA_BLOOM_FILTER_NAME, publicKey.getModulus().toString());
    }

    public boolean isProbablyKnown(final RSAPublicKey publicKey) {
        return publicKeyClient.exists(JedisConfig.RSA_BLOOM_FILTER_NAME, publicKey.getModulus().toString());
    }

}
