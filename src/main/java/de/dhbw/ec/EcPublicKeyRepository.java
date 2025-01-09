package de.dhbw.ec;

import org.bouncycastle.jce.interfaces.ECPublicKey;

public interface EcPublicKeyRepository {
    void addPublicKey(ECPublicKey publicKey);
    boolean isProbablyKnown(final ECPublicKey publicKey);
    long getMemoryConsumption();
}
