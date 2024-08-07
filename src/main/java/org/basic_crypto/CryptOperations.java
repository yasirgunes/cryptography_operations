package org.basic_crypto;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.spec.IESParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

public class CryptOperations {
    private static final int RSA_ALGORITHM = 1;
    private static final int ECC_ALGORITHM = 2;

    private int algorithm;
    private final SecureRandom secureRandom = new SecureRandom();

    public CryptOperations(int algorithm) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        Security.addProvider(new BouncyCastleProvider());
        if (algorithm != RSA_ALGORITHM && algorithm != ECC_ALGORITHM) {
            throw new IllegalArgumentException("Unsupported algorithm");
        }
        this.algorithm = algorithm;
    }

    public void generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        PrivateKey privateKey;
        PublicKey publicKey;

        if (this.algorithm == RSA_ALGORITHM) {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
            keyGen.initialize(2048, secureRandom);
            KeyPair keyPair = keyGen.generateKeyPair();
            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();

            System.out.println("Key Pair generated for the algorithm: RSA.");
            System.out.println("Public KEY:\n" + Base64.toBase64String(publicKey.getEncoded()));
            System.out.println("Private KEY:\n" + Base64.toBase64String(privateKey.getEncoded()));
        } else { // this.algorithm == ECC_ALGORITHM => ECC
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
            keyGen.initialize(ecSpec, secureRandom);
            KeyPair keyPair = keyGen.generateKeyPair();
            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();

            System.out.println("Key Pair generated for the algorithm: ECC.");
            System.out.println("Public KEY: " + Base64.toBase64String(publicKey.getEncoded()));
            System.out.println("Private KEY: " + Base64.toBase64String(privateKey.getEncoded()));
        }
    }

    public PublicKey getPublicKeyFromString(String publicKeyStr) throws Exception {
        try {
            byte[] keyBytes = Base64.decode(publicKeyStr.trim());
            KeyFactory keyFactory = KeyFactory.getInstance(this.algorithm == RSA_ALGORITHM ? "RSA" : "EC", "BC");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            return keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new Exception("Error while getting public key from string", e);
        }
    }

    public PrivateKey getPrivateKeyFromString(String privateKeyStr) throws Exception {
        try {
            byte[] keyBytes = Base64.decode(privateKeyStr.trim());
            KeyFactory keyFactory = KeyFactory.getInstance(this.algorithm == RSA_ALGORITHM ? "RSA" : "EC", "BC");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            return keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new Exception("Error while getting private key from string", e);
        }
    }

    public byte[] encryptData(byte[] data, PublicKey publicKey) throws Exception {
        try {
            Cipher cipher;
            if (this.algorithm == RSA_ALGORITHM) {
                cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
                cipher.init(Cipher.ENCRYPT_MODE, publicKey, secureRandom);
            } else {
                cipher = Cipher.getInstance("ECIES", "BC");
                IESParameterSpec paramSpec = new IESParameterSpec(null, null, 128);
                cipher.init(Cipher.ENCRYPT_MODE, publicKey, paramSpec, secureRandom);
            }
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new Exception("Error while encrypting data", e);
        }
    }

    public byte[] decryptData(byte[] data, PrivateKey privateKey) throws Exception {
        try {
            Cipher cipher;
            if (this.algorithm == RSA_ALGORITHM) {
                cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
                cipher.init(Cipher.DECRYPT_MODE, privateKey, secureRandom);
            } else {
                cipher = Cipher.getInstance("ECIES", "BC");
                IESParameterSpec paramSpec = new IESParameterSpec(null, null, 128);
                cipher.init(Cipher.DECRYPT_MODE, privateKey, paramSpec, secureRandom);
            }
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new Exception("Error while decrypting data", e);
        }
    }

    public byte[] signData(byte[] data, PrivateKey privateKey) throws Exception {
        try {
            Signature signature = Signature.getInstance(this.algorithm == RSA_ALGORITHM ? "SHA256withRSA" : "SHA256withECDSA", "BC");
            signature.initSign(privateKey, secureRandom);
            signature.update(data);
            return signature.sign();
        } catch (Exception e) {
            throw new Exception("Error while signing data", e);
        }
    }

    public boolean verifySignature(byte[] data, byte[] signatureBytes, PublicKey publicKey) throws Exception {
        try {
            Signature signature = Signature.getInstance(this.algorithm == RSA_ALGORITHM ? "SHA256withRSA" : "SHA256withECDSA", "BC");
            signature.initVerify(publicKey);
            signature.update(data);
            return signature.verify(signatureBytes);
        } catch (Exception e) {
            throw new Exception("Error while verifying signature", e);
        }
    }
}
