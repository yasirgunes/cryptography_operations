package org.basic_crypto;

import org.bouncycastle.util.encoders.Base64;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

public class Main {

    public static final String RED = "\033[0;31m";
    public static final String GREEN = "\033[0;32m";
    public static final String YELLOW = "\033[0;33m";
    public static final String RESET = "\033[0m";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        CryptOperations cryptOperations = null;
        boolean isExit = false;
        boolean isAlgorithmExit = false; // to exit completely

        while (!isAlgorithmExit) {
            isExit = false;

            System.out.println("Select Algorithm:");
            System.out.println("1) RSA");
            System.out.println("2) ECC");
            System.out.println("3) Exit from the program");
            System.out.print("> ");

            int algorithmChoice = Integer.parseInt(scanner.nextLine());

            if(algorithmChoice == 3) {
                isAlgorithmExit = true;
                continue;
            }

            while (!isExit) {

                System.out.println("What operation you want to implement? (Current Algorithm: " + (algorithmChoice == 1 ? "RSA" : "ECC") + ")");
                System.out.println("1) Generate Key Pair");
                System.out.println("2) Encrypt Data");
                System.out.println("3) Decrypt Data");
                System.out.println("4) Sign Data");
                System.out.println("5) Verify Signature");
                System.out.println("6) Exit (Back to Algorithm Selection)");
                System.out.print("> ");
                int choice = Integer.parseInt(scanner.nextLine());

                if (choice == 6) {
                    isExit = true;
                    continue;
                }

                try {
                    cryptOperations = new CryptOperations(algorithmChoice);
                } catch (Exception e) {
                    e.printStackTrace();
                    continue;
                }

                switch (choice) {
                    case 1: // Generate Key Pair
                        try {
                            cryptOperations.generateKeyPair();
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                        break;
                    case 2: // Encrypt Data
                        System.out.print("Enter a string: ");
                        String dataToEncrypt = scanner.nextLine();
                        System.out.print("Enter the public key: ");
                        String publicKeyStr = scanner.nextLine().trim();
                        try {
                            PublicKey publicKey = cryptOperations.getPublicKeyFromString(publicKeyStr);
                            byte[] encryptedData = cryptOperations.encryptData(dataToEncrypt.getBytes(), publicKey);
                            System.out.println("Encrypted Data:");
                            System.out.println(Base64.toBase64String(encryptedData));
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                        break;
                    case 3: // Decrypt Data
                        System.out.print("Enter the encrypted data: ");
                        String encryptedDataStr = scanner.nextLine().trim();
                        System.out.print("Enter the private key: ");
                        String privateKeyStr = scanner.nextLine().trim();
                        try {
                            PrivateKey privateKey = cryptOperations.getPrivateKeyFromString(privateKeyStr);
                            byte[] decryptedData = cryptOperations.decryptData(Base64.decode(encryptedDataStr), privateKey);
                            System.out.println("Decrypted Data:");
                            System.out.println(new String(decryptedData));

                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                        break;
                    case 4: // Sign Data
                        System.out.print("Enter a string: ");
                        String dataToSign = scanner.nextLine();
                        System.out.print("Enter the private key: ");
                        String privateKeyStrForSign = scanner.nextLine().trim();
                        try {
                            PrivateKey privateKey = cryptOperations.getPrivateKeyFromString(privateKeyStrForSign);
                            byte[] signature = cryptOperations.signData(dataToSign.getBytes(), privateKey);
                            System.out.println("Signature:\n" + YELLOW + Base64.toBase64String(signature) + RESET);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                        break;
                    case 5: // Verify Signature
                        System.out.print("Enter a string to verify its signature: ");
                        String dataToVerify = scanner.nextLine();
                        System.out.print("Enter the signature: ");
                        String signatureStr = scanner.nextLine().trim();
                        System.out.print("Enter the public key: ");
                        String publicKeyStrForVerify = scanner.nextLine().trim();
                        try {
                            PublicKey publicKey = cryptOperations.getPublicKeyFromString(publicKeyStrForVerify);
                            boolean isVerified = cryptOperations.verifySignature(dataToVerify.getBytes(), Base64.decode(signatureStr), publicKey);
                            System.out.println("Signature Verified: " + isVerified);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                        break;
                    default:
                        System.out.println("Invalid choice. Please try again.");
                }

                System.out.println("Do you want to continue? (y/n)");
                System.out.print("> ");
                String cont = scanner.nextLine().trim();
                if (cont.equalsIgnoreCase("n")) {
                    isExit = true;
                }

                System.out.print("\033[H\033[2J");
                System.out.flush();
            }
        }


        scanner.close();
    }
}
