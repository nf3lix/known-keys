package de.dhbw.rsa;

import de.dhbw.JedisConfig;
import io.rebloom.client.Client;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.math.BigInteger;

@Service
public class RsaPublicKeyService {

    @Autowired
    private Client publicKeyClient;

    public void addPublicKey(final BigInteger modulus) {
        publicKeyClient.add(JedisConfig.RSA_BLOOM_FILTER_NAME, modulus.toString());
    }

    public boolean isProbablyKnown(final BigInteger modulus) {
        return publicKeyClient.exists(JedisConfig.RSA_BLOOM_FILTER_NAME, modulus.toString());
    }

}
