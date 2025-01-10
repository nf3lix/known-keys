package de.dhbw.ec;

import de.dhbw.AbstractPublicKeyController;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/public-keys/ec")
public class EcPublicKeyController extends AbstractPublicKeyController<ECPublicKey> {
    public EcPublicKeyController(final EcPublicKeyService ecPublicKeyService,
                                 final EcPublicKeyExtractor ecPublicKeyExtractor) {
        super(ecPublicKeyService, ecPublicKeyExtractor);
    }
}
