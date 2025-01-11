package de.dhbw;

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

    @PostMapping(path = "/exists", consumes = {MediaType.MULTIPART_FORM_DATA_VALUE})
    public ResponseEntity<String> keyExists(@RequestParam("file") final MultipartFile file) throws IOException {
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

    @PostMapping(consumes = {MediaType.MULTIPART_FORM_DATA_VALUE})
    public ResponseEntity<String> uploadKey(@RequestParam("file") final MultipartFile file) throws IOException {
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

    @GetMapping(path = "redis-memory-consumption")
    public ResponseEntity<String> getMemoryConsumption() {
        return ResponseEntity.ok(String.valueOf(publicKeyService.getMemoryConsumption()));
    }

}
