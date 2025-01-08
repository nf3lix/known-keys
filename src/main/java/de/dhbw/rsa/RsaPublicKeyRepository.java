package de.dhbw.rsa;

import java.security.interfaces.RSAPublicKey;

public interface RsaPublicKeyRepository {
    void addPublicKey(RSAPublicKey publicKey);
    boolean isProbablyKnown(RSAPublicKey publicKey);
}
