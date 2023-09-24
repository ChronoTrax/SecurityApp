package tools;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.KeySpec;
import javax.crypto.SecretKeyFactory;
import java.util.Base64;

import static gui.MainGUI.masterPassword;

public class test {
    public static void main(String[] args) throws Exception {
        // User-provided master password
        String masterPassword = "MySecretPassword123";

        // Derive a secret key from the master password using a key derivation function (e.g., PBKDF2)
        byte[] salt = "RandomSalt".getBytes(); // You should generate a unique salt for each user
        int iterations = 10000; // Number of iterations
        int keyLength = 128; // Key length in bits

        KeySpec keySpec = new javax.crypto.spec.PBEKeySpec(masterPassword.toCharArray(), salt, iterations, keyLength);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(keyFactory.generateSecret(keySpec).getEncoded(), "AES");

        // Create a Cipher object for encryption
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        // Encrypt some plaintext
        byte[] plaintext = "Hello, World!".getBytes();
        byte[] ciphertext = cipher.doFinal(plaintext);

        System.out.println("Plaintext: " + new String(plaintext));
        System.out.println("Ciphertext: " + Base64.getEncoder().encodeToString(ciphertext));
    }
}
