package de.dhbw;

import org.bouncycastle.openssl.PEMException;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class PEMFileValidator {

    public static void validatePEMFile(final MultipartFile file) throws IOException {
        final String content = new String(file.getBytes(), StandardCharsets.UTF_8).trim();
        if (!isValidPEMPublicKey(content) &&
                !isValidPEMRSAPrivateKey(content) &&
                !isValidPEMCert(content) &&
                !isValidPEMECPrivateKey(content)
        ) {
            throw new PEMException("Invalid PEM file");
        }
    }

    private static boolean isValidPEMPublicKey(final String content) {
        return content.startsWith("-----BEGIN PUBLIC KEY-----") && content.endsWith("-----END PUBLIC KEY-----");
    }

    private static boolean isValidPEMRSAPrivateKey(final String content) {
        return content.startsWith("-----BEGIN RSA PRIVATE KEY-----") && content.endsWith("-----END RSA PRIVATE KEY-----");
    }

    private static boolean isValidPEMECPrivateKey(final String content) {
        return content.startsWith("-----BEGIN EC PRIVATE KEY-----") && content.endsWith("-----END EC PRIVATE KEY-----");
    }

    private static boolean isValidPEMCert(final String content) {
        return content.startsWith("-----BEGIN CERTIFICATE-----") && content.endsWith("-----END CERTIFICATE-----");
    }

}
