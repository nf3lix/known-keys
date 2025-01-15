package de.dhbw.rsa;

import de.dhbw.AbstractPublicKeyExtractor;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMException;
import org.springframework.stereotype.Component;

import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

/**
 * Class for extracting RSAPublicKey from an object
 */
@Component
public class RsaPublicKeyExtractor extends AbstractPublicKeyExtractor<RSAPublicKey> {

    @Override
    protected boolean isValidKeyType(final PublicKey publicKey) {
        return publicKey instanceof RSAPublicKey;
    }

    @Override
    protected RSAPublicKey castKey(final PublicKey publicKey) {
        return (RSAPublicKey) publicKey;
    }

    /**
     * Returns RSAPublicKey from an object. Currently supported classes besides those of the base class are: PrivateKeyInfo
     * @param pemObject generic object
     * @return extracted RSAPublicKey
     * @throws PEMException if provided object is not instance of a supported class
     * @throws NoSuchAlgorithmException if a public key needs to be constructed from a provided private key and given algorithm is not known
     * @throws NoSuchProviderException if a public key needs to be constructed from a provided private key and given provider is not known
     * @throws InvalidKeySpecException if a public key needs to be constructed from a provided private key and key spec is not valid
     */
    @Override
    public RSAPublicKey getPublicKey(final Object pemObject) throws PEMException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        if (pemObject instanceof PrivateKeyInfo privateKeyInfo) {
            final PrivateKey privateKey = converter.getPrivateKey(privateKeyInfo);
            final RSAPrivateCrtKey rsaPrivateCrtKey = (RSAPrivateCrtKey) privateKey;
            final RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(
                    rsaPrivateCrtKey.getModulus(), rsaPrivateCrtKey.getPublicExponent());
            KeyFactory keyFactory;
            keyFactory = KeyFactory.getInstance("RSA", "BC");
            return (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
        } else {
            return super.getPublicKey(pemObject);
        }
    }

}
