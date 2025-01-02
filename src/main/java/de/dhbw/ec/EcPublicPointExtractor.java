package de.dhbw.ec;

import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.security.PublicKey;

public class EcPublicPointExtractor {

    private static final JcaPEMKeyConverter converter = new JcaPEMKeyConverter();

    private sealed interface PublicPointExtractor permits PEMKeyPairExtractor {
        ECPoint getPublicPoint(Object pemObject) throws PEMException;
    }

    private static final class PEMKeyPairExtractor implements PublicPointExtractor {
        @Override
        public ECPoint getPublicPoint(final Object pemObject) throws PEMException {
            final PEMKeyPair pemKeyPair = (PEMKeyPair) pemObject;
            final PublicKey publicKey = converter.getPublicKey(pemKeyPair.getPublicKeyInfo());
            final ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
            final ECParameterSpec ecParameterSpec = ecPublicKey.getParameters();
            return ecParameterSpec.getG().getDetachedPoint();
        }
    }

    public static ECPoint getPublicPointFromPemObject(final Object pemObject) throws PEMException {
        final PublicPointExtractor publicPointExtractor = new PEMKeyPairExtractor();
        return publicPointExtractor.getPublicPoint(pemObject);
    }

}

