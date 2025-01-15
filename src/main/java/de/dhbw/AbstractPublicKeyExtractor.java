package de.dhbw;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

/**
 * Base class for extracting a Public Key object from a generic object as provided in the controller class
 * @param <K> the type of Public Keys that are subject to the service (e.g. RSAPublicKey)
 */
public abstract class AbstractPublicKeyExtractor<K extends PublicKey> implements PublicKeyExtractor<K> {

    protected final JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
    protected abstract boolean isValidKeyType(PublicKey publicKey);
    protected abstract K castKey(PublicKey publicKey) throws PEMException;

    /**
     * Returns a Public Key object from a generic object, depending on its class. Currently supported classes:
     * PEMKeyPair, SubjectPublicKeyInfo, X509CertificateHolder. This method might be overwritten, depending on the
     * used cryptosystem.
     * @param pemObject generic object
     * @return Public Key object, depending on K (e.g. RSAPublicKey)
     * @throws PEMException if provided object is not instance of a supported class
     * @throws NoSuchAlgorithmException if a public key needs to be constructed and given algorithm is not known (e.g. when a class overriding this method creates a public key from a private key)
     * @throws NoSuchProviderException if a public key needs to be constructed and given provider is not known (e.g. when a class overriding this method creates a public key from a private key)
     * @throws InvalidKeySpecException if a public key needs to be constructed and the key spec is invalid (e.g. when a class overriding this method creates a public key from a private key)
     */
    @Override
    public K getPublicKey(final Object pemObject) throws PEMException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        try {
            if (pemObject instanceof PEMKeyPair pemKeyPair) {
                final PublicKey publicKey = converter.getPublicKey(pemKeyPair.getPublicKeyInfo());
                return getKeyFromPublicKey(publicKey);
            } else if (pemObject instanceof SubjectPublicKeyInfo subjectPublicKeyInfo) {
                final PublicKey publicKey = converter.getPublicKey(subjectPublicKeyInfo);
                return getKeyFromPublicKey(publicKey);
            } else if (pemObject instanceof X509CertificateHolder x509CertificateHolder) {
                final PublicKey publicKey = converter.getPublicKey(x509CertificateHolder.getSubjectPublicKeyInfo());
                return getKeyFromPublicKey(publicKey);
            } else {
                throw new PEMException("Invalid PEM object");
            }
        } catch (final Exception e) {
            throw new PEMException("Invalid PEM file", e);
        }
    }

    private K getKeyFromPublicKey(PublicKey publicKey) throws PEMException {
        if (isValidKeyType(publicKey)) {
            return castKey(publicKey);
        } else {
            throw new PEMException("Public key is not an instance of expected type");
        }
    }

}
