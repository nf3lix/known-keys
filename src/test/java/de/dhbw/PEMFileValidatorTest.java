package de.dhbw;

import org.bouncycastle.openssl.PEMException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.mock.web.MockMultipartFile;

import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class PEMFileValidatorTest {

    @Test
    void testValidPEMFile() {
        final String pemContent = """
                -----BEGIN PUBLIC KEY-----
                MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALSp6jVkvF0lRMCKP4wwM9DkpUetdatC
                2F3sEPzWjDrOb7R7qfw4w7kZWo0CMEGskm1XulfjQ3Gv5uu70jBexqsCAwEAAQ==
                -----END PUBLIC KEY-----""";
        final MockMultipartFile file = new MockMultipartFile("key.pem", pemContent.getBytes(StandardCharsets.UTF_8));
        assertDoesNotThrow(() -> PEMFileValidator.validatePEMFile(file));
    }

    @ParameterizedTest
    @MethodSource("invalidPEMFileProvider")
    public void testInvalidPEMFile(final String content) {
        final MockMultipartFile file = new MockMultipartFile("key.pem", content.getBytes(StandardCharsets.UTF_8));
        assertThrows(PEMException.class, () -> PEMFileValidator.validatePEMFile(file));
    }

    private static Stream<String> invalidPEMFileProvider() {
        return Stream.of(
                """
                -----BEGIN PUBLIC KEY-----
                INVALID_CONTENT
                -----END PUBLIC KEY-----""",
                """
                MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALSp6jVkvF0lRMCKP4wwM9DkpUetdatC
                2F3sEPzWjDrOb7R7qfw4w7kZWo0CMEGskm1XulfjQ3Gv5uu70jBexqsCAwEAAQ==""",
                """
                -----BEGIN PUBLIC KEY-----
                ===
                -----END PUBLIC KEY-----""",
                """
                -----BEGIN PUBLIC KEY----------END PUBLIC KEY-----""",
                """
                -----BEGIN PUBLIC KEY-----
                MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALSp6jVkvF0lRMCKP4wwM9DkpUetdatC
                2F3sEPzWjDrOb7R7qfw4w7kZWo0CMEGskm1XulfjQ3Gv5uu70jBexqsCAwEAAQ=="""
        );
    }

}
