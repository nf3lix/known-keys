package de.dhbw.rsa;

import de.dhbw.AbstractPublicKeyController;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.*;

import java.security.interfaces.RSAPublicKey;

@Tag(name = "RSA Public Key Controller", description = "Upload and check RSA public keys in PEM format")
@RestController
@RequestMapping("/public-keys/rsa")
public class RsaPublicKeyController extends AbstractPublicKeyController<RSAPublicKey> {
    public RsaPublicKeyController(final RsaPublicKeyService rsaPublicKeyService,
                                  final RsaPublicKeyExtractor rsaPublicKeyExtractor) {
        super(rsaPublicKeyService, rsaPublicKeyExtractor);
    }
}
