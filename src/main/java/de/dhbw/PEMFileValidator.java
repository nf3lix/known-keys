package de.dhbw;

import org.bouncycastle.openssl.PEMException;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static java.util.Map.*;

/**
 * Utility class for validating uploaded PEM files, as there seems to be no standard library for this purpose
 * and validating uploaded files is considered a security best practice
 */
public class PEMFileValidator {

    private PEMFileValidator() {}

    /**
     * Validates a given PEM file by checking for header and footer line and valid base64 content. Raises PEMException
     * when input is not valid. This method might need some more work in the future.
     * @param file the MultipartFile to validate
     * @throws IOException thrown when reading file content fails.
     */
    public static void validatePEMFile(final MultipartFile file) throws IOException {
        final String content = new String(file.getBytes(), StandardCharsets.UTF_8).trim();
        final Entry<String, String> matchingMarker = getMatchingPEMMarker(content);
        if (matchingMarker == null) {
            throw new PEMException("Invalid PEM file: Missing valid header and footer");
        }
        final String base64Content = extractBase64PEMContent(content, matchingMarker.getKey(), matchingMarker.getValue());
        if (!isValidBase64(base64Content)) {
            throw new PEMException("Invalid PEM file: Base64 content is invalid");
        }
    }

    private static final List<Map.Entry<String, String>> PEM_FILE_MARKERS = Arrays.asList(
            entry("-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----"),
            entry("-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----"),
            entry("-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----"),
            entry("-----BEGIN EC PRIVATE KEY-----", "-----END EC PRIVATE KEY-----"),
            entry("-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----")
    );

    private static Entry<String, String> getMatchingPEMMarker(final String content) {
        return PEM_FILE_MARKERS.stream()
                .filter(marker -> content.startsWith(marker.getKey()) && content.endsWith(marker.getValue()))
                .findFirst()
                .orElse(null);
    }

    private static String extractBase64PEMContent(final String content, final String header, final String footer) {
        int start = content.indexOf(header) + header.length();
        int end = content.lastIndexOf(footer);
        if (start >= end) {
            return "";
        }
        final String base64WithoutHeader = content.substring(start, end).trim();
        return base64WithoutHeader.replaceAll("\\s", "");
    }

    private static boolean isValidBase64(final String base64Content) {
        if (!base64Content.matches("^[A-Za-z0-9+/=]+$")) {
            return false;
        }
        try {
            Base64.getDecoder().decode(base64Content);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

}
