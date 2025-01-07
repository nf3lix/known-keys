package de.dhbw.ec;

import org.bouncycastle.jce.interfaces.ECPublicKey;
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

import static de.dhbw.PEMFileValidator.validatePEMFile;

@RestController
@RequestMapping("/public-keys/ec")
public class EcPublicKeyController {

    private final EcPublicKeyService ecPublicKeyService;

    public EcPublicKeyController(EcPublicKeyService ecPublicKeyService) {
        this.ecPublicKeyService = ecPublicKeyService;
    }

    @PostMapping(path = "/exists", consumes = {MediaType.MULTIPART_FORM_DATA_VALUE})
    public ResponseEntity<String> keyExists(@RequestParam("file") final MultipartFile file) throws IOException {
        validatePEMFile(file);
        try (PEMParser pemParser = new PEMParser(new InputStreamReader(file.getInputStream()))) {
            final ECPublicKey publicKey = EcPublicKeyExtractor.getEcPublicKeyFromPemObject(pemParser.readObject());
            final boolean exists = ecPublicKeyService.isProbablyKnown(publicKey);
            return ResponseEntity.ok("Key known: " + exists);
        } catch (IOException e) {
            throw new PEMException("Could not read key file: " + file.getName(), e);
        }
    }

    @PostMapping(consumes = {MediaType.MULTIPART_FORM_DATA_VALUE})
    public ResponseEntity<String> uploadFile(@RequestParam("file") final MultipartFile file) throws IOException {
        validatePEMFile(file);
        try (PEMParser pemParser = new PEMParser(new InputStreamReader(file.getInputStream()))) {
            final ECPublicKey publicKey = EcPublicKeyExtractor.getEcPublicKeyFromPemObject(pemParser.readObject());
            ecPublicKeyService.addPublicKey(publicKey);
            return ResponseEntity.ok("Public key stored successfully");
        } catch (IOException e) {
            throw new PEMException("Could not read key file: " + file.getName(), e);
        }
    }

}
