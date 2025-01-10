package de.dhbw;

import java.security.PublicKey;

public interface PublicKeyRepository<T extends PublicKey> {
    void addPublicKey(T publicKey);
    boolean isProbablyKnown(T publicKey);
    long getMemoryConsumption();
}
