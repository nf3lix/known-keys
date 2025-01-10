package de.dhbw.rsa;

import de.dhbw.GlobalExceptionHandler;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.stream.Stream;

import static de.dhbw.PublicKeyControllerTestUtil.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(RsaPublicKeyController.class)
@Import(GlobalExceptionHandler.class)
public class RsaPublicKeyControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ResourceLoader resourceLoader;

    @MockitoBean
    private RsaPublicKeyExtractor rsaPublicKeyExtractor;

    @MockitoBean
    private RsaPublicKeyService publicKeyService;

    @BeforeEach
    void setUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @ParameterizedTest
    @MethodSource("provideRsaKeyResources")
    public void testRsaKeyExists(final String resourcePath) throws Exception {
        final MockMultipartFile mockFile = getMockMultipartFile(resourceLoader, resourcePath);
        final RSAPublicKey publicKey = rsaPublicKey(
                new BigInteger("9462127310943028450513446955298051246068106169818976319508148622091607268242929842057464753432526034171966724638379914356963896019954886942531223946184363"), BigInteger.valueOf(65537));
        when(publicKeyService.isProbablyKnown(any())).thenReturn(true);
        when(rsaPublicKeyExtractor.getPublicKey(any())).thenReturn(publicKey);

        mockMvc.perform(multipart("/public-keys/rsa/exists")
                        .file(mockFile))
                .andExpect(status().isOk())
                .andExpect(content().string("Key known: true"));
        verify(publicKeyService).isProbablyKnown(publicKey);
    }

    @ParameterizedTest
    @MethodSource("provideRsaKeyResources")
    public void testRsaKeyUpload(final String resourcePath) throws Exception {
        final MockMultipartFile mockFile = getMockMultipartFile(resourceLoader, resourcePath);
        final RSAPublicKey publicKey = rsaPublicKey(
                new BigInteger("9462127310943028450513446955298051246068106169818976319508148622091607268242929842057464753432526034171966724638379914356963896019954886942531223946184363"), BigInteger.valueOf(65537));
        when(publicKeyService.isProbablyKnown(any())).thenReturn(true);
        when(rsaPublicKeyExtractor.getPublicKey(any())).thenReturn(publicKey);

        mockMvc.perform(multipart("/public-keys/rsa")
                        .file(mockFile))
                .andExpect(status().isOk())
                .andExpect(content().string("Public key stored successfully"));
        verify(publicKeyService).addPublicKey(publicKey);
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
                Arguments.of("/public-keys/rsa/exists", invalidPemMockMultipartFile()),
                Arguments.of("/public-keys/rsa", invalidPemMockMultipartFile()),
                Arguments.of("/public-keys/rsa/exists", emptyMockMultipartFile()),
                Arguments.of("/public-keys/rsa", emptyMockMultipartFile())
        );
    }

    private static Stream<Arguments> provideRsaKeyResources() {
        return Stream.of(
                Arguments.of("classpath:rsa/TEST_RSA_PUBLIC_KEY.PEM"),
                Arguments.of("classpath:rsa/TEST_RSA_PRIVATE_KEY.PEM"),
                Arguments.of("classpath:rsa/TEST_RSA_CERT.PEM")
        );
    }

    private static RSAPublicKey rsaPublicKey(final BigInteger modulus, final BigInteger publicExponent) throws Exception {
        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
        return (RSAPublicKey) keyFactory.generatePublic(rsaPublicKeySpec);
    }

}
