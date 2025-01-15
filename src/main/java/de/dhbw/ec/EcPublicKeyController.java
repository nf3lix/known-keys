package de.dhbw.ec;

import de.dhbw.AbstractPublicKeyController;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.springframework.web.bind.annotation.*;

@Tag(name = "Ec Public Key Controller", description = "Upload and check EC public keys in PEM format")
@RestController
@RequestMapping("/public-keys/ec")
public class EcPublicKeyController extends AbstractPublicKeyController<ECPublicKey> {
    public EcPublicKeyController(final EcPublicKeyService ecPublicKeyService,
                                 final EcPublicKeyExtractor ecPublicKeyExtractor) {
        super(ecPublicKeyService, ecPublicKeyExtractor);
    }
}
