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
     * @param userPass Password for current site
     * @param salt A randomly generated salt
     * @return char[]
     * @throws Exception could be illegal block size, padding, or {@link java.security.NoSuchAlgorithmException}
     */
    public static String encryptUserPassword(char[] masterPass, char[] userPass, byte[] salt) throws Exception {
        // Convert char[] password to byte[] for later use
        byte[] masterPasswordBytes = new String(masterPass).getBytes();
        byte[] userPasswordBytes = new String(userPass).getBytes();

        KeySpec masterKeySpec = new PBEKeySpec(masterPass, salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(SECRET_KEY_ALGORITHM);
        SecretKey masterKey = factory.generateSecret(masterKeySpec);

        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, masterKey);

        byte[] encryptedPassword = cipher.doFinal(userPasswordBytes);

        return Base64.getEncoder().encodeToString(encryptedPassword);
    }

    /**
     *
     * @param masterPass Master password for user
     * @param encryptedUserPass Password for current site
     * @param salt A randomly generated salt
     * @return char[]
     * @throws Exception could be illegal block size, padding, or {@link java.security.NoSuchAlgorithmException}
     */
    public static char[] decryptUserPassword(char[] masterPass, String encryptedUserPass, byte[] salt) throws Exception {
        // Convert char[] master password to byte[]
        byte[] masterPassBytes = new String(masterPass).getBytes();

        KeySpec masterKeySpec = new PBEKeySpec(encryptedUserPass.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(SECRET_KEY_ALGORITHM);
        SecretKey masterKey = factory.generateSecret(masterKeySpec);

        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, masterKey);

        byte[] decryptedPasswordBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedUserPass));

        // Convert byte[] decrypted password to char[]
        return new String(decryptedPasswordBytes).toCharArray();
     }
}
