package de.dhbw;

import org.bouncycastle.openssl.PEMException;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

public interface PublicKeyExtractor<K extends PublicKey> {
    K getPublicKey(Object pemObject) throws PEMException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException;
}
