package de.dhbw.ec;

import de.dhbw.GlobalExceptionHandler;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.ResourceLoader;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.stream.Stream;

import static de.dhbw.PublicKeyControllerTestUtil.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(EcPublicKeyController.class)
@Import(GlobalExceptionHandler.class)
public class EcPublicKeyControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ResourceLoader resourceLoader;

    @MockitoBean
    private EcPublicKeyExtractor ecPublicKeyExtractor;

    @MockitoBean
    private EcPublicKeyService publicKeyService;

    @BeforeEach
    void setUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @ParameterizedTest
    @MethodSource("provideEcKeyResources")
    public void testEcKeyExists(final String resourcePath) throws Exception {
        final MockMultipartFile mockFile = getMockMultipartFile(resourceLoader, resourcePath);
        when(publicKeyService.isProbablyKnown(any())).thenReturn(true);
        when(ecPublicKeyExtractor.getPublicKey(any())).thenReturn(publicKeyStub());

        mockMvc.perform(multipart("/public-keys/ec/exists")
                        .file(mockFile))
                .andExpect(status().isOk())
                .andExpect(content().string("Key known: true"));
        verify(publicKeyService).isProbablyKnown(publicKeyStub());
    }

    @ParameterizedTest
    @MethodSource("provideEcKeyResources")
    public void testEcKeyUpload(final String resourcePath) throws Exception {
        final MockMultipartFile mockFile = getMockMultipartFile(resourceLoader, resourcePath);
        when(publicKeyService.isProbablyKnown(any())).thenReturn(true);
        when(ecPublicKeyExtractor.getPublicKey(any())).thenReturn(publicKeyStub());

        mockMvc.perform(multipart("/public-keys/ec")
                        .file(mockFile))
                .andExpect(status().isOk())
                .andExpect(content().string("Public key stored successfully"));
        verify(publicKeyService).addPublicKey(publicKeyStub());
    }

    @ParameterizedTest
    @MethodSource("provideInvalidFileTestData")
    public void testInvalidFileHandling(final String endpoint, final MockMultipartFile file) throws Exception {
        mockMvc.perform(multipart(endpoint)
                        .file(file))
                .andExpect(status().is4xxClientError())
                .andExpect(content().string("Invalid key file provided."));

        verifyNoInteractions(publicKeyService);
    }

    private static Stream<Arguments> provideInvalidFileTestData() {
        return Stream.of(
                Arguments.of("/public-keys/ec/exists", invalidPemMockMultipartFile()),
                Arguments.of("/public-keys/ec", invalidPemMockMultipartFile()),
                Arguments.of("/public-keys/ec/exists", emptyMockMultipartFile()),
                Arguments.of("/public-keys/ec", emptyMockMultipartFile())
        );
    }

    private static Stream<Arguments> provideEcKeyResources() {
        return Stream.of(
                Arguments.of("classpath:ec/TEST_EC_PUBLIC_KEY.PEM"),
                Arguments.of("classpath:ec/TEST_EC_PRIVATE_KEY.PEM"),
                Arguments.of("classpath:ec/TEST_EC_CERT.PEM")
        );
    }

    private static ECPublicKey publicKeyStub() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        return publicKeyFrom("secp256r1", ecPoint(
                "42134508838896037615597729412571348241399061755847904145515134493259224923712",
                "94962155699533225367980242393929424288013306610435794966719739023909263200356"
        ));
    }

    private static ECPoint ecPoint(final String x, final String y) {
        final ECCurve curve = new SecP256R1Curve();
        final BigInteger xCoord = new BigInteger(x);
        final BigInteger yCoord = new BigInteger(y);
        return curve.createPoint(xCoord, yCoord);
    }

    private static ECPublicKey publicKeyFrom(final String curve, final ECPoint point) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        final ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(curve);
        final ECParameterSpec ecParameterSpec = new ECParameterSpec(
                ecSpec.getCurve(),
                ecSpec.getG(),
                ecSpec.getN(),
                ecSpec.getH()
        );

        final ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, ecParameterSpec);
        final KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
        return (ECPublicKey) keyFactory.generatePublic(pubKeySpec);
    }

}
