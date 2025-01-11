package de.dhbw.rsa;

import de.dhbw.AbstractPublicKeyController;
import de.dhbw.GlobalExceptionHandler;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.util.stream.Stream;

import static de.dhbw.PublicKeyControllerTestUtil.*;
import static de.dhbw.rsa.RsaTestUtils.rsaPublicKey;
import static org.junit.jupiter.api.Assertions.assertThrows;
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

    @Test
    void testEndpointIOException() throws IOException {
        AbstractPublicKeyController<RSAPublicKey> publicKeyController = new AbstractPublicKeyController<>(publicKeyService, rsaPublicKeyExtractor) {
        };
        final MultipartFile fileMock = mock(MultipartFile.class);
        when(fileMock.getOriginalFilename()).thenReturn("file");
        when(fileMock.getContentType()).thenReturn(MediaType.MULTIPART_FORM_DATA_VALUE);
        when(fileMock.getBytes()).thenReturn("-----BEGIN CERTIFICATE-----test-----END CERTIFICATE-----".getBytes());
        doThrow(new IOException("Test IOException")).when(fileMock).getInputStream();
        assertThrows(PEMException.class, () -> publicKeyController.keyExists(fileMock));
        assertThrows(PEMException.class, () -> publicKeyController.uploadKey(fileMock));
    }

    @Test
    public void testMemoryConsumption() throws Exception {
        when(publicKeyService.getMemoryConsumption()).thenReturn(10L);
        mockMvc.perform(get("/public-keys/rsa/redis-memory-consumption"))
                .andExpect(status().isOk())
                .andExpect(content().string("10"));
        verify(publicKeyService).getMemoryConsumption();
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

}
