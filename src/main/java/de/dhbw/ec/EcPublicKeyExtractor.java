package de.dhbw.ec;

import de.dhbw.AbstractPublicKeyExtractor;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.springframework.stereotype.Component;

import java.security.PublicKey;

@Component
public class EcPublicKeyExtractor extends AbstractPublicKeyExtractor<ECPublicKey> {

    @Override
    protected boolean isValidKeyType(PublicKey publicKey) {
        return publicKey instanceof ECPublicKey;
    }

    @Override
    protected ECPublicKey castKey(PublicKey publicKey) {
        return (ECPublicKey) publicKey;
    }

}

