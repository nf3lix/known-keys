package de.dhbw;

import org.bouncycastle.openssl.PEMException;

import java.security.PublicKey;

public interface PublicKeyExtractor<K extends PublicKey> {
    K getPublicKey(Object pemObject) throws PEMException;
}
