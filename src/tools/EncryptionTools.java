package tools;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.util.Base64;

public class EncryptionTools {
    private static final String ENCRYTPION_ALGORITHM = "AES";
    private static final String SECRET_KEY_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int KEY_LENGTH = 256; // Key size in bits
    private static final int ITERATIONS = 10000; // Number of iterations, can change

    /**
     *
     * @param pass
     * @param salt
     * @return
     * @throws Exception
     */
    public static String encryptPassword(char[] pass, String salt) throws Exception {
        // Convert char[] password to byte[] for later use
        byte[] passwordBytes = new String(pass).getBytes();

        KeySpec spec = new PBEKeySpec(pass, salt.getBytes(), ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(SECRET_KEY_ALGORITHM);
        SecretKey key = factory.generateSecret(spec);

        Cipher cipher = Cipher.getInstance(ENCRYTPION_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedPassword = cipher.doFinal(passwordBytes);
        return Base64.getEncoder().encodeToString(encryptedPassword);
    }

    /**
     *
     * @param encryptedPass
     * @param salt
     * @return
     * @throws Exception
     */
    public static char[] decryptPassword(String encryptedPass, String salt) throws Exception {
        KeySpec spec = new PBEKeySpec(encryptedPass.toCharArray(), salt.getBytes(), ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(SECRET_KEY_ALGORITHM);
        SecretKey key = factory.generateSecret(spec);

        Cipher cipher = Cipher.getInstance(ENCRYTPION_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedPasswordBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedPass));

        // Convert byte[] decrypted password to char[]
        return new String(decryptedPasswordBytes).toCharArray();
     }
}
