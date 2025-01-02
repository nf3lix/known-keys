package de.dhbw.ec;

import de.dhbw.JedisConfig;
import io.rebloom.client.Client;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.math.ec.ECPoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class EcPublicKeyService {

    @Autowired
    private Client publicKeyClient;

    public void addPublicKey(final ECPublicKey publicKey) {
        final ECPoint publicKeyPoint = publicKey.getQ();
        final String xCoordinate = publicKeyPoint.getDetachedPoint().getXCoord().toBigInteger().toString();
        publicKeyClient.add(JedisConfig.EC_BLOOM_FILTER_NAME, xCoordinate);
    }

    public boolean isProbablyKnown(final ECPublicKey publicKey) {
        final ECPoint publicKeyPoint = publicKey.getQ();
        final String xCoordinate = publicKeyPoint.getDetachedPoint().getXCoord().toBigInteger().toString();
        return publicKeyClient.exists(JedisConfig.EC_BLOOM_FILTER_NAME, xCoordinate);
    }

}
