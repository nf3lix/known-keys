package de.dhbw.rsa;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

public class RsaPublicKeyExtractor {

    private static final JcaPEMKeyConverter converter = new JcaPEMKeyConverter();

    private sealed interface PublicKeyExtractor permits PEMKeyPairExtractor, PrivateKeyInfoExtractor, SubjectPublicKeyInfoExtractor, X509CertificateHolderExtractor {
        RSAPublicKey getPublicKey(Object pemObject) throws PEMException;
    }

    private static final class PEMKeyPairExtractor implements PublicKeyExtractor {
        @Override
        public RSAPublicKey getPublicKey(final Object pemObject) throws PEMException {
            final PEMKeyPair pemKeyPair = (PEMKeyPair) pemObject;
            final PublicKey publicKey = converter.getPublicKey(pemKeyPair.getPublicKeyInfo());
            return (RSAPublicKey) publicKey;
        }
    }

    private static final class PrivateKeyInfoExtractor implements PublicKeyExtractor {
        @Override
        public RSAPublicKey getPublicKey(final Object pemObject) throws PEMException {
            final PrivateKeyInfo privateKeyInfo = (PrivateKeyInfo) pemObject;
            final PrivateKey privateKey = converter.getPrivateKey(privateKeyInfo);
            RSAPrivateCrtKey rsaPrivateCrtKey = (RSAPrivateCrtKey) privateKey;
            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(
                    rsaPrivateCrtKey.getModulus(), rsaPrivateCrtKey.getPublicExponent());
            KeyFactory keyFactory;
            try {
                keyFactory = KeyFactory.getInstance("RSA");
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
            try {
                return (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
            } catch (InvalidKeySpecException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private static final class SubjectPublicKeyInfoExtractor implements PublicKeyExtractor {
        @Override
        public RSAPublicKey getPublicKey(final Object pemObject) throws PEMException {
            final SubjectPublicKeyInfo subjectPublicKeyInfo = (SubjectPublicKeyInfo) pemObject;
            final PublicKey publicKey = converter.getPublicKey(subjectPublicKeyInfo);
            return (RSAPublicKey) publicKey;
        }
    }

    private static final class X509CertificateHolderExtractor implements PublicKeyExtractor {
        @Override
        public RSAPublicKey getPublicKey(final Object pemObject) throws PEMException {
            final X509CertificateHolder x509CertificateHolder = (X509CertificateHolder) pemObject;
            final SubjectPublicKeyInfo subjectPublicKeyInfo = x509CertificateHolder.getSubjectPublicKeyInfo();
            final PublicKey publicKey = converter.getPublicKey(subjectPublicKeyInfo);
            return (RSAPublicKey) publicKey;
        }
    }

    private static PublicKeyExtractor getExtractor(final Object pemObject) throws PEMException {
        return switch (pemObject) {
            case PEMKeyPair ignored -> new PEMKeyPairExtractor();
            case PrivateKeyInfo ignored -> new PrivateKeyInfoExtractor();
            case SubjectPublicKeyInfo ignored -> new SubjectPublicKeyInfoExtractor();
            case X509CertificateHolder ignored -> new X509CertificateHolderExtractor();
            default -> throw new PEMException("Invalid PEM object");
        };
    }

    public static RSAPublicKey getRsaPublicKeyFromPemObject(final Object pemObject) throws PEMException {
        final PublicKeyExtractor extractor = getExtractor(pemObject);
        return extractor.getPublicKey(pemObject);
    }

}
