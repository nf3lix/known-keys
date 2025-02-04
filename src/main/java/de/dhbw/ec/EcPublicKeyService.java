package de.dhbw.ec;

import de.dhbw.PublicKeyRepository;
import de.dhbw.PublicKeyService;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.springframework.stereotype.Service;

@Service
public class EcPublicKeyService implements PublicKeyService<ECPublicKey> {

    private final PublicKeyRepository<ECPublicKey> ecPublicKeyRepository;

    public EcPublicKeyService(final PublicKeyRepository<ECPublicKey> ecPublicKeyRepository) {
        this.ecPublicKeyRepository = ecPublicKeyRepository;
    }

    public void addPublicKey(final ECPublicKey publicKey) {
        ecPublicKeyRepository.addPublicKey(publicKey);
    }

    public boolean isProbablyKnown(final ECPublicKey publicKey) {
        return ecPublicKeyRepository.isProbablyKnown(publicKey);
    }

    public long getMemoryConsumption() {
        return ecPublicKeyRepository.getMemoryConsumption();
    }

}
