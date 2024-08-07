package org.basic_crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.util.encoders.Base64;

import static org.basic_crypto.Main.RED;
import static org.basic_crypto.Main.GREEN;
import static org.basic_crypto.Main.RESET;

public class CryptOperations {

    private int algorithm; // 1 = RSA, 2 = ECC
    private final SecureRandom secureRandom = new SecureRandom();

    public CryptOperations(int algorithm) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        Security.addProvider(new BouncyCastleProvider());
        this.algorithm = algorithm;
    }

    public void generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        PrivateKey privateKey;
        PublicKey publicKey;

        if (this.algorithm == 1) {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
            keyGen.initialize(2048, secureRandom);
            KeyPair keyPair = keyGen.generateKeyPair();
            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();

            System.out.println("Key Pair generated for the algorithm: RSA.");
            System.out.println("Public KEY:\n" + GREEN + Base64.toBase64String(publicKey.getEncoded()) + RESET);
            System.out.println("Private KEY:\n" + RED + Base64.toBase64String(privateKey.getEncoded()) + RESET);
        } else { // this.algorithm == 2 => ECC
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
            keyGen.initialize(ecSpec, secureRandom);
            KeyPair keyPair = keyGen.generateKeyPair();
            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();

            System.out.println("Key Pair generated for the algorithm: ECC.");
            System.out.println("Public KEY:\n" + GREEN + Base64.toBase64String(publicKey.getEncoded()) + RESET);
            System.out.println("Private KEY:\n" + RED + Base64.toBase64String(privateKey.getEncoded()) + RESET);
        }
    }

    // encryption and decryption
    public byte[] encryptData(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(this.algorithm == 1 ? "RSA/ECB/PKCS1Padding" : "ECIES", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    public byte[] decryptData(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(this.algorithm == 1 ? "RSA/ECB/PKCS1Padding" : "ECIES", "BC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    // signing and verification
    public byte[] signData(byte[] data, PrivateKey privateKey) throws Exception {
        String algoParameter = this.algorithm == 1 ? "SHA256withRSA" : "SHA256withECDSA";
        Signature signature = Signature.getInstance(algoParameter, "BC");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    public boolean verifySignature(byte[] data, byte[] signatureBytes, PublicKey publicKey) throws Exception {
        String algoParameter = this.algorithm == 1 ? "SHA256withRSA" : "SHA256withECDSA";
        Signature signature = Signature.getInstance(algoParameter, "BC");
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }

    // helper functions
    public PublicKey getPublicKeyFromString(String publicKeyStr) throws Exception {
        try {
            byte[] keyBytes = Base64.decode(publicKeyStr.trim());
            KeyFactory keyFactory = KeyFactory.getInstance(this.algorithm == 1 ? "RSA" : "EC", "BC");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            return keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new Exception("Error while getting public key from string", e);
        }
    }

    public PrivateKey getPrivateKeyFromString(String privateKeyStr) throws Exception {
        byte[] keyBytes = Base64.decode(privateKeyStr.trim());
        KeyFactory keyFactory = KeyFactory.getInstance(this.algorithm == 1 ? "RSA" : "EC", "BC");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        return keyFactory.generatePrivate(keySpec);
    }
}
