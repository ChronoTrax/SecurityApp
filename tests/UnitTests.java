import org.junit.Test;
import tools.EncryptionTools;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

import static org.junit.Assert.*;

public class UnitTests {
    @Test
    public void testEncryption() throws Exception {
        char[] masterPass = "aaa".toCharArray();
        char[] original = "Hello World!".toCharArray();
        byte[] salt = EncryptionTools.generateSalt();
        String encrypt = EncryptionTools.encryptUserPassword(masterPass, original, salt);
        System.out.println(encrypt);
        char[] decrypt = EncryptionTools.decryptUserPassword(masterPass, encrypt, salt);
        System.out.println(decrypt);
        assertArrayEquals(original, decrypt);
    }

    @Test
    public void testAESMAsterPassword() throws Exception {
        String plaintext = "testtesttesttest";
        String masterPassword = "test"; // Replace with your master password

        // Convert the master password to a byte array
        byte[] keyBytes = plaintext.getBytes();

        // Ensure the key length is compatible with AES (128, 192, or 256 bits)
        if (keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32) {
            throw new IllegalArgumentException("Invalid key length. It should be 16, 24, or 32 bytes.");
        }

        // Create a SecretKeySpec from the master password
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

        // Create a Cipher object for encryption
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        // Encrypt the plaintext
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());

        // Print the ciphertext (base64 encoded for readability)
        String ciphertext = Base64.getEncoder().encodeToString(encryptedBytes);
        System.out.println("Ciphertext: " + ciphertext);

        // Decrypt the ciphertext
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        String decryptedText = new String(decryptedBytes);

        // Print the decrypted plaintext
        System.out.println("Decrypted Text: " + decryptedText);
        assertEquals(decryptedText, plaintext);
    }
}
