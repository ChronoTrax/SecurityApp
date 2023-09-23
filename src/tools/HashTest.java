package tools;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashTest {

    /**
     * This function takes in a filepath (absolute) and converts the data to a byte array. Then, that gets digested and
     * converted into another byte array, which gets output as a {@link String}.
     * @param filepath the absolute filepath that the user selects
     * @return a {@link BigInteger} that refers to the hash data of the file uploaded.
     * @throws IOException error while accessing/reading information in the file
     * @throws NoSuchAlgorithmException when an algorithm is requested but not available
     */
    public static String getMD5(String filepath) throws IOException, NoSuchAlgorithmException {
        byte[] data = Files.readAllBytes(Paths.get(filepath));
        byte[] hash = MessageDigest.getInstance("MD5").digest(data);

        return new BigInteger(1, hash).toString(16);
    }
}
