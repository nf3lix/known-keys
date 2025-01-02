package de.dhbw.rsa;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertThrows;

public class PemRsaExtractorTest {

    @BeforeEach
    void setUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void getPublicKeyFromPEMKeyPair() throws IOException {
        final String testPrivateKeyPair = """
                -----BEGIN RSA PRIVATE KEY-----
                MIIBOQIBAAJBAJ+E+gdRqePIUTvZosN5sxHN5KqkGC90FE61qmXEO4xCd3NNVmXv
                d4EODs9JsRRogZkOOkVoaUd5udAynracDAsCAwEAAQJADdPoHJROpskpiYefHVTC
                WgvAA66/zfVBAWWsBLBS/SBuN7VQX4AhEKPhO7xfTtFsNPHXNoaGaaS2yGEnpHux
                IQIhAKfGIiHb8rju5HTTdBJ/5wt0lasP0kxDpY7+Y3KXpWfRAiEA82edB4eqnXXd
                ocB1uXlM08+SMV9qimtJWwg/YH/3yRsCIHKbrbtVhfSA9L09qX/tsYYoyQkHENCa
                MWGCM6sXHp3RAiAgzklC140uVdF+WJNFYUzyi1p33xVb/KPRaiYomnbKGwIgUs6J
                t6Hb59N5BUnIjLkT5xCwbpIGbMuxHntOQp8OgBI=
                -----END RSA PRIVATE KEY-----
                """;
        final PEMKeyPair keyPair = readPEMKeyPair(testPrivateKeyPair);
        final RSAPublicKey rsaPublicKey = PemRsaExtractor.getRsaPublicKeyFromPemObject(keyPair);
        assert Objects.equals(rsaPublicKey.getPublicExponent(), BigInteger.valueOf(65537));
        assert Objects.equals(rsaPublicKey.getModulus(), new BigInteger("8354710993758221462700056916743654678562458316647327533676261208190915370309700546509009539702734965121185359189735771167596256616153280001625727457561611"));
    }

    @Test
    public void getPublicKeyFromPrivateKeyInfo() throws IOException {
        final String testPrivateKeyInfo = """
                -----BEGIN RSA PRIVATE KEY-----
                MIIBPAIBAAJBAPAx88NsQW4/A2/JJrcZHSP+KD7qLtIyJ5qss+rWy+7+j7iBIDE5
                JaLMjCvnrKfcDpHNSut5RB9UM3uIsbdNTtMCAwEAAQJAbETH8S3J7Izg2rGcDup2
                FTRKJdnfkwXijjkMvG1n7WjX6/soyPbcyIIloz3YEjj2RRcMTymDu626KoH5C8C1
                eQIhAP/wAo/5au4c4AnEf2CEUsWine4EAe7Vvq5e6m+xgtMXAiEA8ED1ayKsItEp
                eQ8HNduv05+PTMQyhtH239DisBl7Z6UCIQDVf9PDYp7uzyudOku/qeKad1MjUDiE
                kc2lDAyo6/1kNQIhAMkFYRMSQLslDTFofJz4wsYrxGfz5V7fAVRF39Z+i72tAiEA
                0c7rjUo9hd88FWbHegre5wS6HfZ+0Zw0UkzY5RAeyEA=
                -----END RSA PRIVATE KEY-----
                """;
        final PrivateKeyInfo keyInfo = readPrivateKeyInfo(testPrivateKeyInfo);
        final RSAPublicKey rsaPublicKey = PemRsaExtractor.getRsaPublicKeyFromPemObject(keyInfo);
        assert Objects.equals(rsaPublicKey.getPublicExponent(), BigInteger.valueOf(65537));
        assert Objects.equals(rsaPublicKey.getModulus(), new BigInteger("12580039500852756484105714571772544426383396946885710400699434543206965072549168777678738858898337340443808731666387363484786064605609573759112437618790099"));
    }

    @Test
    public void getPublicKeySubjectPublicKeyInfo() throws Exception {
        final String testPublicKey = """
                -----BEGIN PUBLIC KEY-----
                MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALSp6jVkvF0lRMCKP4wwM9DkpUetdatC
                2F3sEPzWjDrOb7R7qfw4w7kZWo0CMEGskm1XulfjQ3Gv5uu70jBexqsCAwEAAQ==
                -----END PUBLIC KEY-----
                """;
        final SubjectPublicKeyInfo keyInfo = readSubjectPublicKeyInfo(testPublicKey);
        final RSAPublicKey rsaPublicKey = PemRsaExtractor.getRsaPublicKeyFromPemObject(keyInfo);
        assert Objects.equals(rsaPublicKey.getPublicExponent(), BigInteger.valueOf(65537));
        assert Objects.equals(rsaPublicKey.getModulus(), new BigInteger("9462127310943028450513446955298051246068106169818976319508148622091607268242929842057464753432526034171966724638379914356963896019954886942531223946184363"));
    }

    @Test
    public void getPublicKeyFromX509CertHolder() throws Exception {
        final String testCert = """
                -----BEGIN CERTIFICATE-----
                MIIBIDCBy6ADAgECAgYBlCiibJYwDQYJKoZIhvcNAQELBQAwEjEQMA4GA1UEAwwH
                VGVzdCBDQTAeFw0yNTAxMDEyMDA4NDBaFw0yNTAxMDMyMDA4NDBaMBsxGTAXBgNV
                BAMMEFRlc3QgQ2VydGlmaWNhdGUwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAst05
                jHPYsUscEeL1V6qf/6oiuHusaPGwd7bprsjvfn1htSNy65xuB+T5TnxG5VkQjfFr
                qX1vCbFH8m9vPGHEcQIDAQABMA0GCSqGSIb3DQEBCwUAA0EAr2DDPEquDRFIjGv7
                C85J6t3TSotnawZq6AINULuVbnae/bHG9IbTqbQc9muTsHzSGa51BqZ4cd1txfFP
                829Mpg==
                -----END CERTIFICATE-----
                """;

        final X509CertificateHolder certificateHolder = readX509CertificateHolder(testCert);
        final RSAPublicKey rsaPublicKey = PemRsaExtractor.getRsaPublicKeyFromPemObject(certificateHolder);
        assert Objects.equals(rsaPublicKey.getPublicExponent(), BigInteger.valueOf(65537));
        assert Objects.equals(rsaPublicKey.getModulus(), new BigInteger("9367876150072090697440066621288661310608885474889923310005709210929803520665733645389903314573454165424857725023366367246023683414250447546346372052665457"));
    }

    @Test
    public void throwExceptionOnInvalidPemObject() {
        assertThrows(PEMException.class, () -> PemRsaExtractor.getRsaPublicKeyFromPemObject("test_input"));
    }

    private static PEMKeyPair readPEMKeyPair(final String privateKeyPEM) throws IOException {
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

    private static PrivateKeyInfo readPrivateKeyInfo(final String privateKeyPEM) throws IOException {
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

    private static SubjectPublicKeyInfo readSubjectPublicKeyInfo(final String publicKey) throws IOException {
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

    private static X509CertificateHolder readX509CertificateHolder(final String certificate) throws IOException  {
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
