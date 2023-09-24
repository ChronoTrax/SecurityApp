package tools;

import gui.MainGUI;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;

public class EncryptionTools {
    private static final String ENCRYPTION_ALGORITHM = "AES/ECB/PKCS5Padding";
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
    public static String encryptPassword(char[] pass, byte[] salt) throws Exception {
        KeySpec spec = new PBEKeySpec(pass, salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(ENCRYPTION_ALGORITHM);
        SecretKey key = factory.generateSecret(spec);

        Cipher cipher = Cipher.getInstance(SECRET_KEY_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedPassword = cipher.doFinal();

        return Base64.getEncoder().encodeToString(encryptedPassword);
    }

    /**
     *
     * @param encryptedPass
     * @param salt
     * @return
     * @throws Exception
     */
    public static String decryptPassword(char[] encryptedPass, byte[] salt) throws Exception {
        KeySpec spec = new PBEKeySpec(encryptedPass, salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(Arrays.toString(MainGUI.masterPassword));
        SecretKey key = factory.generateSecret(spec);

        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedPasswordBytes = cipher.doFinal(Base64.getDecoder().decode(Arrays.toString(encryptedPass)));

        return new String(decryptedPasswordBytes);
     }

}
