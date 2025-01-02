package de.dhbw.rsa;

import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMParser;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStreamReader;
import java.security.interfaces.RSAPublicKey;

@RestController
@RequestMapping("/public-keys/rsa")
public class RsaPublicKeyController {

    private final RsaPublicKeyService rsaPublicKeyService;

    public RsaPublicKeyController(final RsaPublicKeyService rsaPublicKeyService) {
        this.rsaPublicKeyService = rsaPublicKeyService;
    }

    @PostMapping(path = "/exists", consumes = {MediaType.MULTIPART_FORM_DATA_VALUE})
    public ResponseEntity<String> keyExists(@RequestParam("file") final MultipartFile file) throws IOException {
        if (file.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Please select a file to upload.");
        }
        try (PEMParser pemParser = new PEMParser(new InputStreamReader(file.getInputStream()))) {
            final RSAPublicKey publicKey = PemRsaExtractor.getRsaPublicKeyFromPemObject(pemParser.readObject());
            final boolean exists = rsaPublicKeyService.isProbablyKnown(publicKey);
            return ResponseEntity.ok("Key known: " + exists);
        } catch (IOException e) {
            throw new PEMException("Could not read key file: " + file.getName(), e);
        }
    }

    @PostMapping(consumes = {MediaType.MULTIPART_FORM_DATA_VALUE})
    public ResponseEntity<String> uploadKey(@RequestParam("file") final MultipartFile file) throws IOException {
        if (file.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Please select a file to upload.");
        }
        try (PEMParser pemParser = new PEMParser(new InputStreamReader(file.getInputStream()))) {
            final RSAPublicKey publicKey = PemRsaExtractor.getRsaPublicKeyFromPemObject(pemParser.readObject());
            rsaPublicKeyService.addPublicKey(publicKey);
            return ResponseEntity.ok("Key stored successfully");
        } catch (IOException e) {
            throw new PEMException("Could not read key file: " + file.getName(), e);
        }
    }

}
