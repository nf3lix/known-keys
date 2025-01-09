package de.dhbw.rsa;

import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStreamReader;
import java.security.interfaces.RSAPublicKey;

import static de.dhbw.PEMFileValidator.validatePEMFile;

@RestController
@RequestMapping("/public-keys/rsa")
public class RsaPublicKeyController {

    private final RsaPublicKeyService rsaPublicKeyService;
    private static final Logger logger = LoggerFactory.getLogger(RsaPublicKeyController.class);

    public RsaPublicKeyController(final RsaPublicKeyService rsaPublicKeyService) {
        this.rsaPublicKeyService = rsaPublicKeyService;
    }

    @PostMapping(path = "/exists", consumes = {MediaType.MULTIPART_FORM_DATA_VALUE})
    public ResponseEntity<String> keyExists(@RequestParam("file") final MultipartFile file) throws IOException {
        validatePEMFile(file);
        try (PEMParser pemParser = new PEMParser(new InputStreamReader(file.getInputStream()))) {
            final Object o = pemParser.readObject();
            final RSAPublicKey publicKey = RsaPublicKeyExtractor.getRsaPublicKeyFromPemObject(o);
            final boolean exists = rsaPublicKeyService.isProbablyKnown(publicKey);
            return ResponseEntity.ok("Key known: " + exists);
        } catch (IOException e) {
            throw new PEMException("Could not read empty file: " + file.getName(), e);
        }
    }

    @PostMapping(consumes = {MediaType.MULTIPART_FORM_DATA_VALUE})
    public ResponseEntity<String> uploadKey(@RequestParam("file") final MultipartFile file) throws IOException {
        validatePEMFile(file);
        try (PEMParser pemParser = new PEMParser(new InputStreamReader(file.getInputStream()))) {
            final RSAPublicKey publicKey = RsaPublicKeyExtractor.getRsaPublicKeyFromPemObject(pemParser.readObject());
            rsaPublicKeyService.addPublicKey(publicKey);
            logger.info("Public key stored successfully");
            return ResponseEntity.ok("Public key stored successfully");
        } catch (IOException e) {
            throw new PEMException("Could not read key file: " + file.getName(), e);
        }
    }

    @GetMapping(path = "/redis-memory-consumption")
    public ResponseEntity<String> getMemoryConsumption() {
        return ResponseEntity.ok(String.valueOf(rsaPublicKeyService.getMemoryConsumption()));
    }

}
