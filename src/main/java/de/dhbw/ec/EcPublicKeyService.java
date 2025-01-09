package de.dhbw.ec;

import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.springframework.stereotype.Service;

@Service
public class EcPublicKeyService {

    private final EcPublicKeyRepository ecPublicKeyRepository;

    public EcPublicKeyService(EcPublicKeyRepository ecPublicKeyRepository) {
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
