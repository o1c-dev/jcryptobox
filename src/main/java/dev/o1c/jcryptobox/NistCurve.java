package dev.o1c.jcryptobox;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

// based on:
// https://github.com/google/tink/blob/e767489e11f66d162637f73dbe75eee6e44a3208/java_src/src/main/java/com/google/crypto/tink/subtle/EllipticCurves.java
enum NistCurve {
    P256("115792089210356248762697446949407573530086143415290314195533631308867097853951",
            "115792089210356248762697446949407573529996955224135760342422259061068512044369",
            "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");

    private final EllipticCurve curve;
    private final ECParameterSpec parameterSpec;

    NistCurve(String decimalP, String decimalN, String hexB, String hexGX, String hexGY) {
        BigInteger p = new BigInteger(decimalP);
        BigInteger n = new BigInteger(decimalN);
        BigInteger three = new BigInteger("3");
        BigInteger a = p.subtract(three);
        BigInteger b = new BigInteger(hexB, 16);
        BigInteger gx = new BigInteger(hexGX, 16);
        BigInteger gy = new BigInteger(hexGY, 16);
        int h = 1;
        ECFieldFp fp = new ECFieldFp(p);
        ECPoint g = new ECPoint(gx, gy);
        curve = new EllipticCurve(fp, a, b);
        parameterSpec = new ECParameterSpec(curve, g, n, h);
    }

    public ECPoint decompress(byte[] compressedPoint) {
        try {
            int coordinateSize = fieldSizeInBytes(curve);
            BigInteger p = getModulus(curve);
            if (compressedPoint.length != coordinateSize + 1) {
                throw new IllegalArgumentException("compressed point has wrong length");
            }
            boolean lsb;
            if (compressedPoint[0] == 2) {
                lsb = false;
            } else if (compressedPoint[0] == 3) {
                lsb = true;
            } else {
                throw new IllegalArgumentException("invalid format");
            }
            BigInteger x = new BigInteger(1, Arrays.copyOfRange(compressedPoint, 1, compressedPoint.length));
            if (x.signum() == -1 || x.compareTo(p) >= 0) {
                throw new IllegalArgumentException("x is out of range");
            }
            BigInteger y = getY(x, lsb, curve);
            return new ECPoint(x, y);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public ECPublicKey decodeKey(byte[] key) {
        KeySpec keySpec = new ECPublicKeySpec(decompress(key), parameterSpec);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            return (ECPublicKey) keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static byte[] compress(ECPublicKey key) {
        return compress(key.getW(), key.getParams().getCurve());
    }

    public static byte[] compress(ECPoint point, EllipticCurve ec) {
        try {
            checkPointOnCurve(point, ec);
            int coordinateSize = fieldSizeInBytes(ec);
            byte[] encoded = new byte[coordinateSize + 1];
            byte[] x = point.getAffineX().toByteArray();
            System.arraycopy(x, 0, encoded, 1 + coordinateSize - x.length, x.length);
            encoded[0] = (byte) (point.getAffineY().testBit(0) ? 3 : 2);
            return encoded;
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static void validatePublicKey(ECPublicKey publicKey, ECPrivateKey privateKey) throws InvalidAlgorithmParameterException {
        validatePublicKeySpec(publicKey, privateKey);
        checkPointOnCurve(publicKey.getW(), privateKey.getParams().getCurve());
    }

    private static void checkPointOnCurve(ECPoint point, EllipticCurve ec) throws InvalidAlgorithmParameterException {
        BigInteger p = getModulus(ec);
        BigInteger x = point.getAffineX();
        BigInteger y = point.getAffineY();
        if (x == null || y == null) {
            throw new InvalidAlgorithmParameterException("point is at infinity");
        }
        // Check 0 <= x < p and 0 <= y < p.
        if (x.signum() == -1 || x.compareTo(p) >= 0) {
            throw new InvalidAlgorithmParameterException("x is out of range");
        }
        if (y.signum() == -1 || y.compareTo(p) >= 0) {
            throw new InvalidAlgorithmParameterException("y is out of range");
        }
        // Check y^2 == x^3 + a x + b (mod p)
        BigInteger lhs = y.multiply(y).mod(p);
        BigInteger rhs = x.multiply(x).add(ec.getA()).multiply(x).add(ec.getB()).mod(p);
        if (!lhs.equals(rhs)) {
            throw new InvalidAlgorithmParameterException("Point is not on curve");
        }
    }

    private static int fieldSizeInBytes(EllipticCurve curve) throws InvalidAlgorithmParameterException {
        return (fieldSizeInBits(curve) + 7) / 8;
    }

    private static int fieldSizeInBits(EllipticCurve curve) throws InvalidAlgorithmParameterException {
        return getModulus(curve).subtract(BigInteger.ONE).bitLength();
    }

    private static BigInteger getModulus(EllipticCurve curve) throws InvalidAlgorithmParameterException {
        ECField field = curve.getField();
        if (field instanceof ECFieldFp) {
            return ((ECFieldFp) field).getP();
        } else {
            throw new InvalidAlgorithmParameterException("Only curves over prime order fields are supported");
        }
    }

    private static BigInteger getY(BigInteger x, boolean lsb, EllipticCurve curve) throws InvalidAlgorithmParameterException {
        BigInteger p = getModulus(curve);
        BigInteger a = curve.getA();
        BigInteger b = curve.getB();
        BigInteger rhs = x.multiply(x).add(a).multiply(x).add(b).mod(p);
        BigInteger y = modSqrt(rhs, p);
        if (lsb != y.testBit(0)) {
            y = p.subtract(y).mod(p);
        }
        return y;
    }

    private static BigInteger modSqrt(BigInteger x, BigInteger p) throws InvalidAlgorithmParameterException {
        if (p.signum() != 1) {
            throw new InvalidAlgorithmParameterException("p must be positive");
        }
        x = x.mod(p);
        BigInteger squareRoot = null;
        // Special case for x == 0.
        // This check is necessary for Cipolla's algorithm.
        if (x.equals(BigInteger.ZERO)) {
            return BigInteger.ZERO;
        }
        if (p.testBit(0) && p.testBit(1)) {
            // Case p % 4 == 3
            // q = (p + 1) / 4
            BigInteger q = p.add(BigInteger.ONE).shiftRight(2);
            squareRoot = x.modPow(q, p);
        } else if (p.testBit(0) && !p.testBit(1)) {
            // Case p % 4 == 1
            // For this case we use Cipolla's algorithm.
            // This alogorithm is preferrable to Tonelli-Shanks for primes p where p-1 is divisible by
            // a large power of 2, which is a frequent choice since it simplifies modular reduction.
            BigInteger a = BigInteger.ONE;
            BigInteger d = null;
            BigInteger q1 = p.subtract(BigInteger.ONE).shiftRight(1);
            int tries = 0;
            while (true) {
                d = a.multiply(a).subtract(x).mod(p);
                // Special case d==0. We need d!=0 below.
                if (d.equals(BigInteger.ZERO)) {
                    return a;
                }
                // Computes the Legendre symbol. Using the Jacobi symbol would be a faster.
                BigInteger t = d.modPow(q1, p);
                if (t.add(BigInteger.ONE).equals(p)) {
                    // d is a quadratic non-residue.
                    break;
                } else if (!t.equals(BigInteger.ONE)) {
                    // p does not divide d. Hence, t != 1 implies that p is not a prime.
                    throw new InvalidAlgorithmParameterException("p is not prime");
                } else {
                    a = a.add(BigInteger.ONE);
                }
                tries++;
                // If 128 tries were not enough to find a quadratic non-residue, then it is likely that
                // p is not prime. To avoid an infinite loop in this case we perform a primality test.
                // If p is prime then this test will be done with a negligible probability of 2^{-128}.
                if (tries == 128) {
                    if (!p.isProbablePrime(80)) {
                        throw new InvalidAlgorithmParameterException("p is not prime");
                    }
                }
            }
            // Since d = a^2 - x is a quadratic non-residue modulo p, we have
            //   a - sqrt(d) == (a + sqrt(d))^p (mod p),
            // and hence
            //   x == (a + sqrt(d))(a - sqrt(d)) == (a + sqrt(d))^(p+1) (mod p).
            // Thus if x is square then (a + sqrt(d))^((p+1)/2) (mod p) is a square root of x.
            BigInteger q = p.add(BigInteger.ONE).shiftRight(1);
            BigInteger u = a;
            BigInteger v = BigInteger.ONE;
            for (int bit = q.bitLength() - 2; bit >= 0; bit--) {
                // Square u + v sqrt(d) and reduce mod p.
                BigInteger tmp = u.multiply(v);
                u = u.multiply(u).add(v.multiply(v).mod(p).multiply(d)).mod(p);
                v = tmp.add(tmp).mod(p);
                if (q.testBit(bit)) {
                    // Multiply u + v sqrt(d) by a + sqrt(d) and reduce mod p.
                    tmp = u.multiply(a).add(v.multiply(d)).mod(p);
                    v = a.multiply(v).add(u).mod(p);
                    u = tmp;
                }
            }
            squareRoot = u;
        }
        // The methods used to compute the square root only guarantees a correct result if the
        // preconditions (i.e. p prime and x is a square) are satisfied. Otherwise the value is
        // undefined. Hence it is important to verify that squareRoot is indeed a square root.
        if (squareRoot != null && squareRoot.multiply(squareRoot).mod(p).compareTo(x) != 0) {
            throw new InvalidAlgorithmParameterException("Could not find a modular square root");
        }
        return squareRoot;
    }

    private static void validatePublicKeySpec(ECPublicKey publicKey, ECPrivateKey privateKey)
            throws InvalidAlgorithmParameterException {
        try {
            ECParameterSpec publicKeySpec = publicKey.getParams();
            ECParameterSpec privateKeySpec = privateKey.getParams();
            if (!isSameEcParameterSpec(publicKeySpec, privateKeySpec)) {
                throw new InvalidAlgorithmParameterException("invalid public key spec");
            }
        } catch (IllegalArgumentException | NullPointerException ex) {
            // The Java security providers on Android K and Android L might throw these unchecked
            // exceptions, converting them to a checked one to not crash the JVM.
            throw new InvalidAlgorithmParameterException(ex.toString());
        }
    }

    private static boolean isSameEcParameterSpec(ECParameterSpec one, ECParameterSpec two) {
        return one.getCurve().equals(two.getCurve())
                && one.getGenerator().equals(two.getGenerator())
                && one.getOrder().equals(two.getOrder())
                && one.getCofactor() == two.getCofactor();
    }
}
