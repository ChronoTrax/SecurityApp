package tools;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class EncryptionTools {
    private static final String ENCRYPTION_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String SECRET_KEY_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int KEY_LENGTH = 256; // Key size in bits
    private static final int ITERATIONS = 10000; // Number of iterations, can change

    /**
     * @param masterPass Master password of user
     * @param userPass   Password for current site
     * @param salt       A randomly generated salt
     * @return char[]
     * @throws Exception could be illegal block size, padding, or {@link java.security.NoSuchAlgorithmException}
     */
    public static String encryptUserPassword(char[] masterPass, char[] userPass, byte[] salt) throws Exception {
        // Convert char[] password to byte[] for later use
        byte[] userPasswordBytes = new String(userPass).getBytes();

        SecretKeyFactory factory = SecretKeyFactory.getInstance(SECRET_KEY_ALGORITHM);
        KeySpec masterKeySpec = new PBEKeySpec(masterPass, salt, ITERATIONS, KEY_LENGTH);
        SecretKey masterKey = new SecretKeySpec(factory.generateSecret(masterKeySpec).getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, masterKey, new IvParameterSpec(salt));

        byte[] encryptedPassword = cipher.doFinal(userPasswordBytes);

        return Base64.getEncoder().encodeToString(encryptedPassword);
    }

    /**
     * @param masterPass        Master password for user
     * @param encryptedUserPass Password for current site
     * @param salt              A randomly generated salt
     * @return char[]
     * @throws Exception could be illegal block size, padding, or {@link java.security.NoSuchAlgorithmException}
     */
    public static char[] decryptUserPassword(char[] masterPass, String encryptedUserPass, byte[] salt) throws Exception {
        // Convert char[] master password to byte[]
        byte[] masterPassBytes = new String(masterPass).getBytes();

        SecretKeyFactory factory = SecretKeyFactory.getInstance(SECRET_KEY_ALGORITHM);
        KeySpec masterKeySpec = new PBEKeySpec(masterPass, salt, ITERATIONS, KEY_LENGTH);
        SecretKey masterKey = new SecretKeySpec(factory.generateSecret(masterKeySpec).getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, masterKey, new IvParameterSpec(salt));

        byte[] decryptedPasswordBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedUserPass));

        // Convert byte[] decrypted password to char[]
        return new String(decryptedPasswordBytes).toCharArray();
    }

    /**
     * This function takes in a filepath (absolute) and converts the data to a byte array. Then, that gets digested and
     * converted into another byte array, which gets output as a {@link String}.
     *
     * @param filepath the absolute filepath that the user selects
     * @return a {@link BigInteger}         that refers to the hash data of the file uploaded.
     * @throws IOException              error while accessing/reading information in the file
     * @throws NoSuchAlgorithmException when an algorithm is requested but not available
     */
    public static String calculateMD5(String filepath) throws IOException, NoSuchAlgorithmException {
        byte[] data = Files.readAllBytes(Paths.get(filepath));
        byte[] hash = MessageDigest.getInstance("MD5").digest(data);

        return new BigInteger(1, hash).toString(16);
    }

    /**
     * This function takes in a filepath (absolute) and converts the data to a byte array. Then, that gets digested and
     * converted into another byte array, which gets output as a {@link String}.
     *
     * @param filePath the absolute filepath that the user selects
     * @return a {@link String}             that refers to the hash data of the file uploaded.
     * @throws NoSuchAlgorithmException error while accessing/reading information in the file
     * @throws IOException              when an algorithm is requested but not available
     */
    public static String calculateSHA256(String filePath) throws NoSuchAlgorithmException, IOException {
        byte[] data = Files.readAllBytes(Paths.get(filePath));
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(data);

        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            // used to convert a single byte 'b' into its hexadecimal representation
            // '0xff & b' ensures that the value of 'b' is treated as an unsigned byte
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }

        return hexString.toString();
    }

    /**
     * Generates a (secure)random salt when called
     *
     * @return byte[]
     */
    public static byte[] generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    /**
     * @param password User's password
     * @param salt     A random salt
     * @return byte[]
     * @throws NoSuchAlgorithmException error while accessing/reading information in the file
     * @throws InvalidKeySpecException  Invalid encoding, wrong length, uninitialized
     */
    public static byte[] hashPassword(char[] password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        int iterations = 10000;
        int keyLength = 256;
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return factory.generateSecret(spec).getEncoded();
    }
}
