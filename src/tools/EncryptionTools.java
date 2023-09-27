package tools;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

public class EncryptionTools {
    private static final String ENCRYPTION_ALGORITHM = "AES/CBC/PKCS5Padding";

    private static final String HASHING_ALGORITHM = "SHA-256";

    /**
     * Encrypts the user's password using the master password as the key, with salt to randomize.
     *
     * @param masterPass master password to be used as encryption key.
     * @param userPass   user's password to be encrypted.
     * @param salt       random salt to be used in encryption.
     * @return encrypted user password.
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static char[] encryptUserPassword(char[] masterPass, char[] userPass, byte[] salt)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, getSecretKeySpec(masterPass), new IvParameterSpec(salt));
        return new String(Base64.getEncoder().encode(cipher.doFinal(new String(userPass).getBytes()))).toCharArray();
    }

    /**
     * Decrypts the encrypted user password using the master password and the salt used to generate the encryption.
     *
     * @param masterPass        master password to be used as decryption key.
     * @param encryptedUserPass user's encrypted password to be decrypted.
     * @param salt              salt used when encrypting the password.
     * @return decrypted user password.
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static char[] decryptUserPassword(char[] masterPass, char[] encryptedUserPass, byte[] salt)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, getSecretKeySpec(masterPass), new IvParameterSpec(salt));
        return new String(cipher.doFinal(Base64.getDecoder().decode(new String(encryptedUserPass)))).toCharArray();
    }

    /**
     * Converts the master password into a secure SecretKeySpec.
     *
     * @param masterPass master password used as key.
     * @return SecureKeySpec for use in encryption.
     * @throws NoSuchAlgorithmException
     */
    private static SecretKeySpec getSecretKeySpec(char[] masterPass) throws NoSuchAlgorithmException {
        byte[] keyBytes = new String(masterPass).getBytes();
        MessageDigest sha = MessageDigest.getInstance(HASHING_ALGORITHM);
        byte[] hashedBytes = Arrays.copyOf(sha.digest(keyBytes), 16);
        return new SecretKeySpec(hashedBytes, "AES");
    }

    /**
     * Takes a file at filePath, then returns the MD5 hash of the file.
     *
     * @param filePath path of the file to be hashed.
     * @return String representation of MD5 hash.
     * @throws IOException
     * @throws NoSuchAlgorithmException
     */
    public static String calculateMD5(String filePath) throws IOException, NoSuchAlgorithmException {
        byte[] data = Files.readAllBytes(Paths.get(filePath));

        byte[] hash = MessageDigest.getInstance("MD5").digest(data);

        return new BigInteger(1, hash).toString(16);
    }

    /**
     * Takes a file at filepath, then returns the SHA256 hash of the file.
     *
     * @param filePath path of the file to be hashed.
     * @return String representation of SHA256 hash.
     * @throws IOException
     * @throws NoSuchAlgorithmException
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
     * Generates a secure random salt.
     *
     * @return byte[] salt.
     */
    public static byte[] generateSalt() {
        byte[] salt = new byte[16];

        new SecureRandom().nextBytes(salt);

        return salt;
    }

    /**
     * Hashes a password using the default hashing algorithm (SHA-256).
     *
     * @param password password to be hashed.
     * @return byte[] hash of password.
     * @throws NoSuchAlgorithmException
     */
    public static byte[] hashPassword(char[] password) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(HASHING_ALGORITHM);

        return digest.digest(new String(password).getBytes());
    }
}
