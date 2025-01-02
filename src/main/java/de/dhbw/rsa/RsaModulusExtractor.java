package de.dhbw.rsa;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;

public class RsaModulusExtractor {

    private static final JcaPEMKeyConverter converter = new JcaPEMKeyConverter();

    private sealed interface ModulusExtractor permits PEMKeyPairExtractor, PrivateKeyInfoExtractor, SubjectPublicKeyInfoExtractor {
        BigInteger getModulus(Object pemObject) throws PEMException;
    }

    private static final class PEMKeyPairExtractor implements ModulusExtractor {
        @Override
        public BigInteger getModulus(final Object pemObject) throws PEMException {
            final PEMKeyPair pemKeyPair = (PEMKeyPair) pemObject;
            final PublicKey publicKey = converter.getPublicKey(pemKeyPair.getPublicKeyInfo());
            return ((RSAPublicKey) publicKey).getModulus();
        }
    }

    private static final class PrivateKeyInfoExtractor implements ModulusExtractor {
        @Override
        public BigInteger getModulus(final Object pemObject) throws PEMException {
            final PrivateKeyInfo privateKeyInfo = (PrivateKeyInfo) pemObject;
            final PrivateKey privateKey = converter.getPrivateKey(privateKeyInfo);
            return ((RSAPrivateCrtKey) privateKey).getModulus();
        }
    }

    private static final class SubjectPublicKeyInfoExtractor implements ModulusExtractor {
        @Override
        public BigInteger getModulus(final Object pemObject) throws PEMException {
            final SubjectPublicKeyInfo subjectPublicKeyInfo = (SubjectPublicKeyInfo) pemObject;
            final PublicKey publicKey = converter.getPublicKey(subjectPublicKeyInfo);
            return ((RSAPublicKey) publicKey).getModulus();
        }
    }

    private static ModulusExtractor getExtractor(final Object pemObject) throws PEMException {
        return switch (pemObject) {
            case PEMKeyPair ignored -> new PEMKeyPairExtractor();
            case PrivateKeyInfo ignored -> new PrivateKeyInfoExtractor();
            case SubjectPublicKeyInfo ignored -> new SubjectPublicKeyInfoExtractor();
            default -> throw new PEMException("Invalid PEM object");
        };
    }

    public static BigInteger getModulusFromPemObject(final Object pemObject) throws PEMException {
        final ModulusExtractor extractor = getExtractor(pemObject);
        return extractor.getModulus(pemObject);
    }

}
