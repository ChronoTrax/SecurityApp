import org.junit.Test;
import tools.EncryptionTools;
import tools.HashTools;

import static org.junit.Assert.*;

public class UnitTests {
    @Test
    public void testEncryption() throws Exception {
        String original = "Hello World!";
        byte[] salt = HashTools.generateSalt();
        String encrypt = EncryptionTools.encryptPassword(original.toCharArray(), salt);
        String decrypt = EncryptionTools.decryptPassword(encrypt.toCharArray(), salt);
        assertEquals(original, decrypt);
    }
}
