package de.dhbw.ec;

import de.dhbw.AbstractPublicKeyExtractor;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.springframework.stereotype.Component;

import java.security.PublicKey;

/**
 * Class for extracting ECPublicKey from an object
 */
@Component
public class EcPublicKeyExtractor extends AbstractPublicKeyExtractor<ECPublicKey> {

    @Override
    protected boolean isValidKeyType(final PublicKey publicKey) {
        return publicKey instanceof ECPublicKey;
    }

    @Override
    protected ECPublicKey castKey(final PublicKey publicKey) {
        return (ECPublicKey) publicKey;
    }

}

