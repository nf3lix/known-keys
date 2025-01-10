package de.dhbw.rsa;

import de.dhbw.AbstractPublicKeyController;
import org.springframework.web.bind.annotation.*;

import java.security.interfaces.RSAPublicKey;

@RestController
@RequestMapping("/public-keys/rsa")
public class RsaPublicKeyController extends AbstractPublicKeyController<RSAPublicKey> {
    public RsaPublicKeyController(final RsaPublicKeyService rsaPublicKeyService,
                                  final RsaPublicKeyExtractor rsaPublicKeyExtractor) {
        super(rsaPublicKeyService, rsaPublicKeyExtractor);
    }
}
