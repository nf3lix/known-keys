package de.dhbw.rsa;

import de.dhbw.PublicKeyService;
import org.springframework.stereotype.Service;

import java.security.interfaces.RSAPublicKey;

@Service
public class RsaPublicKeyService implements PublicKeyService<RSAPublicKey> {

    private final RsaPublicKeyRepository rsaPublicKeyRepository;

    public RsaPublicKeyService(final RsaPublicKeyRepository rsaPublicKeyRepository) {
        this.rsaPublicKeyRepository = rsaPublicKeyRepository;
    }

    public void addPublicKey(final RSAPublicKey publicKey) {
        rsaPublicKeyRepository.addPublicKey(publicKey);
    }

    public boolean isProbablyKnown(final RSAPublicKey publicKey) {
        return rsaPublicKeyRepository.isProbablyKnown(publicKey);
    }

    public long getMemoryConsumption() {
        return rsaPublicKeyRepository.getMemoryConsumption();
    }

}
