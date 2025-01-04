package de.dhbw;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;

import java.io.IOException;
import java.io.StringReader;

public class TestUtil {

    public static PEMKeyPair readPEMKeyPair(final String privateKeyPEM) throws IOException {
        try (final StringReader privateKeyReader = new StringReader(privateKeyPEM);
             final PEMParser pemParser = new PEMParser(privateKeyReader)) {
            final Object parsedObject = pemParser.readObject();
            if (parsedObject instanceof PEMKeyPair) {
                return (PEMKeyPair) parsedObject;
            } else {
                throw new IllegalArgumentException("Invalid private key format");
            }
        }
    }

    public static PrivateKeyInfo readPrivateKeyInfo(final String privateKeyPEM) throws IOException {
        try (final StringReader privateKeyReader = new StringReader(privateKeyPEM);
             final PEMParser pemParser = new PEMParser(privateKeyReader)) {
            final Object parsedObject = pemParser.readObject();
            if (parsedObject instanceof final PEMKeyPair keyPair) {
                return keyPair.getPrivateKeyInfo();
            } else {
                throw new IllegalArgumentException("Invalid private key format");
            }
        }
    }

    public static SubjectPublicKeyInfo readSubjectPublicKeyInfo(final String publicKey) throws IOException {
        try (final StringReader privateKeyReader = new StringReader(publicKey);
             final PEMParser pemParser = new PEMParser(privateKeyReader)) {
            final Object parsedObject = pemParser.readObject();
            if (parsedObject instanceof final SubjectPublicKeyInfo subjectPublicKeyInfo) {
                return subjectPublicKeyInfo;
            } else {
                throw new IllegalArgumentException("Invalid private key format");
            }
        }
    }

    public static X509CertificateHolder readX509CertificateHolder(final String certificate) throws IOException  {
        try (final StringReader certReader = new StringReader(certificate);
             final PEMParser pemParser = new PEMParser(certReader)) {
            final Object parsedObject = pemParser.readObject();
            if (parsedObject instanceof final X509CertificateHolder certificateHolder) {
                return certificateHolder;
            } else {
                throw new IllegalArgumentException("Invalid private key format");
            }
        }
    }

}
