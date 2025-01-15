package de.dhbw;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMParser;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStreamReader;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import static de.dhbw.PEMFileValidator.validatePEMFile;

public abstract class AbstractPublicKeyController<K extends PublicKey> {

    private final PublicKeyService<K> publicKeyService;
    private final PublicKeyExtractor<K> publicKeyExtractor;

    protected AbstractPublicKeyController(final PublicKeyService<K> publicKeyService, final PublicKeyExtractor<K> publicKeyExtractor) {
        this.publicKeyService = publicKeyService;
        this.publicKeyExtractor = publicKeyExtractor;
    }

    @Operation(summary = "Check probabilistically if given public key is known.")
    @PostMapping(path = "/exists", consumes = {MediaType.MULTIPART_FORM_DATA_VALUE})
    public ResponseEntity<String> keyExists(@Parameter(description = "Public key in PEM format as Multipart Form Data", required = true)
                                            @RequestParam(name = "file") final MultipartFile file) throws IOException {
        validatePEMFile(file);
        try (PEMParser pemParser = new PEMParser(new InputStreamReader(file.getInputStream()))) {
            final Object pemObject = pemParser.readObject();
            final K publicKey = publicKeyExtractor.getPublicKey(pemObject);
            final boolean exists = publicKeyService.isProbablyKnown(publicKey);
            return ResponseEntity.ok("Key known: " + exists);
        } catch (IOException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            throw new PEMException("Could not read key file: " + file.getName(), e);
        }
    }

    @Operation(summary = "Upload public key")
    @PostMapping(consumes = {MediaType.MULTIPART_FORM_DATA_VALUE})
    public ResponseEntity<String> uploadKey(@Parameter(description = "Public key in PEM format as Multipart Form Data", required = true)
                                            @RequestParam("file") final MultipartFile file) throws IOException {
        validatePEMFile(file);
        try (PEMParser pemParser = new PEMParser(new InputStreamReader(file.getInputStream()))) {
            final Object pemObject = pemParser.readObject();
            final K publicKey = publicKeyExtractor.getPublicKey(pemObject);
            publicKeyService.addPublicKey(publicKey);
            return ResponseEntity.ok("Public key stored successfully");
        } catch (IOException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            throw new PEMException("Could not read key file: " + file.getName(), e);
        }
    }

    @Operation(summary = "Get the current memory consumption of the corresponding redis key")
    @GetMapping(path = "redis-memory-consumption")
    public ResponseEntity<String> getMemoryConsumption() {
        return ResponseEntity.ok(String.valueOf(publicKeyService.getMemoryConsumption()));
    }

}
