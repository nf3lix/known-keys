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

public abstract class AbstractPublicKeyExtractor<K extends PublicKey> implements PublicKeyExtractor<K> {

    protected final JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
    protected abstract boolean isValidKeyType(PublicKey publicKey);
    protected abstract K castKey(PublicKey publicKey) throws PEMException;

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
