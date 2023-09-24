import org.junit.Test;
import tools.EncryptionTools;
import tools.HashTools;

import java.util.Arrays;

import static org.junit.Assert.*;

public class UnitTests {
    @Test
    public void testEncryption() throws Exception {
        char[] masterPass = "TEST".toCharArray();
        String original = "Hello World!";
        byte[] salt = HashTools.generateSalt();
        String encrypt = EncryptionTools.encryptPassword(masterPass, original.toCharArray(), salt);
        char[] decrypt = EncryptionTools.decryptPassword(masterPass, encrypt, salt);
        assertEquals(original, Arrays.toString(decrypt));
    }
}
