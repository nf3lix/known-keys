package de.dhbw.ec;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

public class EcTestUtil {

    static ECPublicKey ecPublicKey(final String curve, final ECPoint point) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        final ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(curve);
        final ECParameterSpec ecParameterSpec = new ECParameterSpec(
                ecSpec.getCurve(),
                ecSpec.getG(),
                ecSpec.getN(),
                ecSpec.getH()
        );

        final ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, ecParameterSpec);
        final KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
        return (ECPublicKey) keyFactory.generatePublic(pubKeySpec);
    }

    static ECPoint ecPoint(final String x, final String y) {
        final ECCurve curve = new SecP256R1Curve();
        final BigInteger xCoord = new BigInteger(x);
        final BigInteger yCoord = new BigInteger(y);
        return curve.createPoint(xCoord, yCoord);
    }

}
