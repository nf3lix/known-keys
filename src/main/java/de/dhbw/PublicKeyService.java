package de.dhbw;

import java.security.PublicKey;

/**
 * Generic service interface for saving public keys and checking whether they are known
 * @param <K> the type of Public Keys that are subject to the service (e.g. RSAPublicKey)
 */
public interface PublicKeyService<K extends PublicKey> {
    boolean isProbablyKnown(K publicKey);
    void addPublicKey(K publicKey);
    long getMemoryConsumption();
}
