package org.basic_crypto;

import org.bouncycastle.util.encoders.Base64;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

public class Main {

    // ANSI escape codes for coloring text
    public static final String RESET = "\033[0m";
    public static final String RED = "\033[0;31m";
    public static final String GREEN = "\033[0;32m";
    public static final String YELLOW = "\033[0;33m";
    public static final String BLUE = "\033[0;34m";
    public static final String PURPLE = "\033[0;35m";
    public static final String CYAN = "\033[0;36m";

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException {
        Scanner scanner = new Scanner(System.in);
        boolean isAlgorithmExit = false;

        while (!isAlgorithmExit) {
            System.out.println(CYAN + "Select Algorithm:" + RESET);
            System.out.println("1) RSA");
            System.out.println("2) ECC");
            System.out.println("3) Exit from the program");
            System.out.println("\n4) Hash a string");
            System.out.print("> ");

            int algorithmChoice = Integer.parseInt(scanner.nextLine());

            if (algorithmChoice == 3) {
                isAlgorithmExit = true;
                System.out.println("Bye.");
                continue;
            }
            else if(algorithmChoice == 4){
                System.out.print("Enter a string: ");
                String dataToHash = scanner.nextLine();
                System.out.println("Hashed Data:");
                System.out.println(GREEN + CryptOperations.hashString(dataToHash) + RESET);

                // ask user do they want to continue
                System.out.println("Do you want to continue? (y/n)");
                System.out.print("> ");
                String cont = scanner.nextLine().trim();
                if (cont.equalsIgnoreCase("n")) {
                    System.out.println("Bye.");
                    isAlgorithmExit = true;
                }
                continue;
            }

            CryptOperations cryptOperations;
            try {
                cryptOperations = new CryptOperations(algorithmChoice);
            } catch (Exception e) {
                System.err.println(RED + "Failed to initialize CryptOperations. Error: " + e.getMessage() + RESET);
                continue;
            }

            boolean isExit = false;
            while (!isExit) {
                System.out.println(BLUE + "What operation do you want to implement? (Current Algorithm: " + (algorithmChoice == 1 ? "RSA" : "ECC") + ")" + RESET);
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

                switch (choice) {
                    case 1:
                        try {
                            cryptOperations.generateKeyPair();
                        } catch (Exception e) {
                            System.err.println(RED + "Failed to generate key pair. Error: " + e.getMessage() + RESET);
                        }
                        break;
                    case 2:
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
                            System.err.println(RED + "Failed to encrypt data. Error: " + e.getMessage() + RESET);
                        }
                        break;
                    case 3:
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
                            System.err.println(RED + "Failed to decrypt data. Error: " + e.getMessage() + RESET);
                        }
                        break;
                    case 4:
                        System.out.print("Enter a string: ");
                        String dataToSign = scanner.nextLine();
                        System.out.print("Enter the private key: ");
                        String privateKeyStrForSign = scanner.nextLine().trim();
                        try {
                            PrivateKey privateKey = cryptOperations.getPrivateKeyFromString(privateKeyStrForSign);
                            byte[] signature = cryptOperations.signData(dataToSign.getBytes(), privateKey);
                            System.out.println("Signature:\n" + YELLOW + Base64.toBase64String(signature) + RESET);
                        } catch (Exception e) {
                            System.err.println(RED + "Failed to sign data. Error: " + e.getMessage() + RESET);
                        }
                        break;
                    case 5:
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
                            System.err.println(RED + "Failed to verify signature. Error: " + e.getMessage() + RESET);
                        }
                        break;
                    default:
                        System.out.println(RED + "Invalid choice. Please try again." + RESET);
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
