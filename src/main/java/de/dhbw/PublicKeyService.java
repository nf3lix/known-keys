package de.dhbw;

import java.security.PublicKey;

public interface PublicKeyService<K extends PublicKey> {
    boolean isProbablyKnown(K publicKey);
    void addPublicKey(K publicKey);
    long getMemoryConsumption();
}
