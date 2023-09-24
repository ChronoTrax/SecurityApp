package tools;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.spec.KeySpec;
import java.util.Base64;

public class EncryptionTools {
    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static final String SECRET_KEY_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int KEY_LENGTH = 256; // Key size in bits
    private static final int ITERATIONS = 10000; // Number of iterations, can change

    /**
     *
     * @param  masterPass Master password of user
     * @param pass Password for current site
     * @param salt A randomly generated salt
     * @return char[]
     * @throws Exception could be illegal block size, padding, or {@link java.security.NoSuchAlgorithmException}
     */
    public static String encryptPassword(char[] masterPass, char[] pass, byte[] salt) throws Exception {
        // Convert char[] password to byte[] for later use
        byte[] passwordBytes = new String(pass).getBytes();

        KeySpec spec = new PBEKeySpec(masterPass, salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(SECRET_KEY_ALGORITHM);
        SecretKey key = factory.generateSecret(spec);

        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedPassword = cipher.doFinal(passwordBytes);

        return Base64.getEncoder().encodeToString(encryptedPassword);
    }

    /**
     *
     * @param masterPass Master password for user
     * @param encryptedPass Password for current site
     * @param salt A randomly generated salt
     * @return char[]
     * @throws Exception could be illegal block size, padding, or {@link java.security.NoSuchAlgorithmException}
     */
    public static char[] decryptPassword(char[] masterPass, String encryptedPass, byte[] salt) throws Exception {
        // Convert char[] master password to byte[]
        byte[] masterPassBytes = new String(masterPass).getBytes();

        KeySpec spec = new PBEKeySpec(encryptedPass.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(SECRET_KEY_ALGORITHM);
        SecretKey key = factory.generateSecret(spec);

        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedPasswordBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedPass));

        // Convert byte[] decrypted password to char[]
        return new String(decryptedPasswordBytes).toCharArray();
     }
}
