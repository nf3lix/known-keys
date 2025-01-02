package de.dhbw.ec;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.security.PublicKey;

public class EcPublicPointExtractor {

    private static final JcaPEMKeyConverter converter = new JcaPEMKeyConverter();

    private sealed interface PublicKeyExtractor permits PEMKeyPairExtractor, X509CertificateHolderExtractor {
        ECPublicKey getPublicKey(Object pemObject) throws PEMException;
    }

    private static final class PEMKeyPairExtractor implements PublicKeyExtractor {
        @Override
        public ECPublicKey getPublicKey(final Object pemObject) throws PEMException {
            final PEMKeyPair pemKeyPair = (PEMKeyPair) pemObject;
            final PublicKey publicKey = converter.getPublicKey(pemKeyPair.getPublicKeyInfo());
            return (ECPublicKey) publicKey;
        }
    }

    private static final class X509CertificateHolderExtractor implements PublicKeyExtractor {
        @Override
        public ECPublicKey getPublicKey(final Object pemObject) throws PEMException {
            final X509CertificateHolder x509CertificateHolder = (X509CertificateHolder) pemObject;
            final SubjectPublicKeyInfo subjectPublicKeyInfo = x509CertificateHolder.getSubjectPublicKeyInfo();
            final PublicKey publicKey = converter.getPublicKey(subjectPublicKeyInfo);
            return (ECPublicKey) publicKey;
        }
    }

    private static PublicKeyExtractor getExtractor(final Object pemObject) throws PEMException {
        return switch (pemObject) {
            case PEMKeyPair ignored -> new PEMKeyPairExtractor();
            case X509CertificateHolder ignored -> new X509CertificateHolderExtractor();
            default -> throw new PEMException("Invalid PEM object");
        };
    }

    public static ECPublicKey getEcPublicKeyFromPemObject(final Object pemObject) throws PEMException {
        final PublicKeyExtractor extractor = getExtractor(pemObject);
        return extractor.getPublicKey(pemObject);
    }

}

