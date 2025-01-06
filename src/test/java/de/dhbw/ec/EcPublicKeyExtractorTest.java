package de.dhbw.ec;

import de.dhbw.rsa.RsaPublicKeyExtractor;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

import static de.dhbw.TestUtil.*;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class EcPublicKeyExtractorTest {

    @BeforeEach
    void setUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void getPublicKeyFromPEMKeyPair() throws IOException {
        final String testPrivateKeyPair = """
                -----BEGIN EC PRIVATE KEY-----
                MHcCAQEEIEWwG/GnVceXk0THOVjrDrer8pboEpo6p8PNKa+E27AcoAoGCCqGSM49
                AwEHoUQDQgAEG5BlVe3c4+AtEGFK4tAEyUV6UTJvhvGMlsDALxV7IEyP4gpASCEQ
                QjCE//yG3Rr83vafVf1nv7H4F3zFjyD6/Q==
                -----END EC PRIVATE KEY-----
                """;
        final PEMKeyPair keyPair = readPEMKeyPair(testPrivateKeyPair);
        final ECPublicKey ecPublicKey = EcPublicKeyExtractor.getEcPublicKeyFromPemObject(keyPair);

        final ECCurve curve = new SecP256R1Curve();
        final BigInteger xHex = new BigInteger("12467572282102654442499181405833496531090552583884637003128218928464447348812");
        final BigInteger yHex = new BigInteger("65080115534543149538371136859567843899013310349629399871054168498913943812861");
        final ECPoint point = curve.createPoint(xHex, yHex);

        assert ecPublicKey.getQ().equals(point);
    }

    @Test
    public void getPublicKeyFromX509CertHolder() throws Exception {
        final String testCert = """
                -----BEGIN CERTIFICATE-----
                MIIBHTCBxaADAgECAghNge3b7BjSyTAKBggqhkjOPQQDAjAVMRMwEQYDVQQDDApU
                ZXN0SXNzdWVyMB4XDTI1MDEwNDE2MDQ1NVoXDTI2MDEwNDE2MDQ1NVowFjEUMBIG
                A1UEAwwLVGVzdFN1YmplY3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQHsi9x
                I7NcwMk102YC9PfVDpUHfw8BjklLj3Kg6p1d8fcyDG2ddVyBTvVlaH//2w+EYyWb
                00ehxXjlm3JxXRy/MAoGCCqGSM49BAMCA0cAMEQCIBZ0YZWZnJaWGbEXw8n/nKs0
                xBu0kt3q7KHwym6WRQ9cAiA2565DWcal9Xvpds9GolKZTjBZHAnza08Hv+AEPlOy
                iA==
                -----END CERTIFICATE-----
                """;

        final X509CertificateHolder certificateHolder = readX509CertificateHolder(testCert);
        final ECPublicKey ecPublicKey = EcPublicKeyExtractor.getEcPublicKeyFromPemObject(certificateHolder);

        final ECCurve curve = new SecP256R1Curve();
        final BigInteger xHex = new BigInteger("3481016149925405259576293977989710538158770666165491448807298223437156015601");
        final BigInteger yHex = new BigInteger("111809701729478374801122797272365083847701066388734389762440362091230466481343");
        final ECPoint point = curve.createPoint(xHex, yHex);
        assert ecPublicKey.getQ().equals(point);
    }

    @Test
    public void getPublicKeyFromPublicKeyInfo() throws IOException {
        final String testPublicKey = """
                -----BEGIN PUBLIC KEY-----
                MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXSdJcWoNZ61BrtHcu9ouSfWf2II/
                EknX0WU9tdOVPkDR8qzoCE7HnFgnyVWH/rXPouFDk6sbsKZNUUQBu8NQZA==
                -----END PUBLIC KEY-----
                """;
        final SubjectPublicKeyInfo keyInfo = readSubjectPublicKeyInfo(testPublicKey);
        final ECPublicKey ecPublicKey = EcPublicKeyExtractor.getEcPublicKeyFromPemObject(keyInfo);
        final ECCurve curve = new SecP256R1Curve();
        final BigInteger xHex = new BigInteger("42134508838896037615597729412571348241399061755847904145515134493259224923712");
        final BigInteger yHex = new BigInteger("94962155699533225367980242393929424288013306610435794966719739023909263200356");
        final ECPoint point = curve.createPoint(xHex, yHex);
        assert ecPublicKey.getQ().equals(point);
    }

    @Test
    public void throwExceptionOnInvalidPemObject() {
        assertThrows(PEMException.class, () -> EcPublicKeyExtractor.getEcPublicKeyFromPemObject("test_input"));
    }

}
