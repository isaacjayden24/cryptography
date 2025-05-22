package Lab1;

import java.util.Scanner;


//lab 1 work

public class StreamCipherAnalysisJava {

    // Function to XOR two hex strings
    public static String xorHexStrings(String hex1, String hex2) {
        int len = Math.min(hex1.length(), hex2.length());
        StringBuilder result = new StringBuilder();

        for (int i = 0; i < len; i += 2) {
            int byte1 = Integer.parseInt(hex1.substring(i, i + 2), 16);
            int byte2 = Integer.parseInt(hex2.substring(i, i + 2), 16);

            int xorByte = byte1 ^ byte2; // XOR operation

            // Convert XOR result to readable ASCII if possible
            char xorChar = (char) xorByte;
            if (Character.isLetterOrDigit(xorChar) || xorChar == ' ') {
                result.append(xorChar);
            } else {
                result.append('.'); // Replace unreadable characters
            }
        }
        return result.toString();
    }

    // Function to recover the key by assuming spaces exist
    public static String recoverKey(String cipherText, String knownPlaintext) {
        StringBuilder key = new StringBuilder();
        for (int i = 0; i < Math.min(cipherText.length(), knownPlaintext.length()); i += 2) {
            int cipherByte = Integer.parseInt(cipherText.substring(i, i + 2), 16);
            int plainByte = (int) knownPlaintext.charAt(i / 2);

            int keyByte = cipherByte ^ plainByte; // XOR to recover key byte
            key.append(String.format("%02x", keyByte));
        }
        return key.toString();
    }

    // Function to decrypt ciphertext using the recovered key
    public static String decryptWithKey(String cipherText, String key) {
        StringBuilder plaintext = new StringBuilder();
        for (int i = 0; i < Math.min(cipherText.length(), key.length()); i += 2) {
            int cipherByte = Integer.parseInt(cipherText.substring(i, i + 2), 16);
            int keyByte = Integer.parseInt(key.substring(i, i + 2), 16);

            int plainByte = cipherByte ^ keyByte; // XOR ciphertext with key
            plaintext.append((char) plainByte);
        }
        return plaintext.toString();
    }

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);

        // Input ciphertexts
        System.out.println("Enter first hex-encoded ciphertext:");
        String hex1 = sc.nextLine();

        System.out.println("Enter second hex-encoded ciphertext:");
        String hex2 = sc.nextLine();

        // Step 1: XOR Ciphertexts to Identify Spaces
        String xorResult = xorHexStrings(hex1, hex2);
        System.out.println("\nXOR Result (Identified Spaces & Letters):");
        System.out.println(xorResult);

        // Step 2: Enter a known plaintext phrase
        System.out.println("\nEnter a known plaintext snippet (guess):");
        String knownPlaintext = sc.nextLine();

        // Step 3: Recover Key
        String recoveredKey = recoverKey(hex1, knownPlaintext);
        System.out.println("\nRecovered Key (Partial): " + recoveredKey);

        // Step 4: Decrypt the Ciphertext
        String decryptedMessage = decryptWithKey(hex1, recoveredKey);
        System.out.println("\nDecrypted Message:");
        System.out.println(decryptedMessage);

        sc.close();
    }
}
