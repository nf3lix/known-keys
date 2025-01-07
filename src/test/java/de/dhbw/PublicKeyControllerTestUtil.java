package de.dhbw;

import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class PublicKeyControllerTestUtil {

    public static MockMultipartFile getMockMultipartFile(final ResourceLoader resourceLoader, final String resourcePath) throws IOException {
        final Resource resource = resourceLoader.getResource(resourcePath);
        return new MockMultipartFile(
                "file",
                "file.key",
                MediaType.TEXT_PLAIN_VALUE,
                Files.readAllBytes(Paths.get(resource.getURI()))
        );
    }

    public static MockMultipartFile emptyMockMultipartFile() {
        return new MockMultipartFile(
                "empty_file",
                "empty_file.key",
                MediaType.TEXT_PLAIN_VALUE,
                new byte[0]
        );
    }

    public static MockMultipartFile invalidPemMockMultipartFile() {
        return new MockMultipartFile(
                "invalid_file",
                "invalid_file.key",
                MediaType.TEXT_PLAIN_VALUE,
                "invalid_content".getBytes());
    }

}
