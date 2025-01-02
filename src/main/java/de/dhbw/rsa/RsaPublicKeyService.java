package de.dhbw.rsa;

import de.dhbw.JedisConfig;
import io.rebloom.client.Client;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.math.BigInteger;

@Service
public class RsaPublicKeyService {

    @Autowired
    private Client bloomFilterClient;

    public void addPublicKey(final BigInteger modulus) {
        bloomFilterClient.add(JedisConfig.RSA_BLOOM_FILTER_NAME, modulus.toString());
    }

    public boolean isProbablyKnown(final BigInteger modulus) {
        return bloomFilterClient.exists(JedisConfig.RSA_BLOOM_FILTER_NAME, modulus.toString());
    }

}
