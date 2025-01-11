package de.dhbw.rsa;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;

public class RsaTestUtils {

    public static RSAPublicKey rsaPublicKey(final BigInteger modulus, final BigInteger publicExponent) throws Exception {
        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
        return (RSAPublicKey) keyFactory.generatePublic(rsaPublicKeySpec);
    }

}
