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

    @Override
    public RSAPublicKey getPublicKey(final Object pemObject) throws PEMException {
        if (pemObject instanceof PrivateKeyInfo privateKeyInfo) {
            final PrivateKey privateKey = converter.getPrivateKey(privateKeyInfo);
            if (privateKey instanceof RSAPrivateCrtKey rsaPrivateCrtKey) {
                RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(
                        rsaPrivateCrtKey.getModulus(), rsaPrivateCrtKey.getPublicExponent());
                KeyFactory keyFactory;
                try {
                    keyFactory = KeyFactory.getInstance("RSA", "BC");
                    return (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
                } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                    throw new PEMException("Error generating public key from private key", e);
                } catch (NoSuchProviderException e) {
                    throw new RuntimeException(e);
                }
            } else {
                throw new PEMException("Private key is not an instance of RSAPrivateCrtKey.");
            }
        } else {
            return super.getPublicKey(pemObject);
        }
    }

}
