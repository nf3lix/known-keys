package de.dhbw.rsa;

import de.dhbw.PublicKeyRepository;
import de.dhbw.PublicKeyService;
import org.springframework.stereotype.Service;

import java.security.interfaces.RSAPublicKey;

@Service
public class RsaPublicKeyService implements PublicKeyService<RSAPublicKey> {

    private final PublicKeyRepository<RSAPublicKey> rsaPublicKeyRepository;

    public RsaPublicKeyService(final PublicKeyRepository<RSAPublicKey> rsaPublicKeyRepository) {
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
