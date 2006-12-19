package org.jasypt.pbe;

import java.util.Arrays;

import junit.framework.TestCase;

public class BytePBEWithMD5AndDESEncryptorTest extends TestCase {

    public void testEncryptAndDecrypt() throws Exception {

        String password = "A PASSWORD BEING SET";
        
        String message = "This is a message";
        byte[] messageBytes = message.getBytes("UTF-8");
        
        BytePBEWithMD5AndDESEncryptor encryptor = 
            new BytePBEWithMD5AndDESEncryptor();
        encryptor.setPassword(password);
        
        for (int i = 0; i < 100; i++) {
            byte[] encryptedMessage = encryptor.encrypt(messageBytes);
            byte[] decryptedMessage = encryptor.decrypt(encryptedMessage);
            assertTrue(Arrays.equals(decryptedMessage, messageBytes));
        }
        
        for (int i = 0; i < 100; i++) {
            assertFalse(
                    Arrays.equals(
                            encryptor.encrypt(messageBytes),
                            encryptor.encrypt(messageBytes)));
        }
        
        BytePBEWithMD5AndDESEncryptor encryptor2 = 
            new BytePBEWithMD5AndDESEncryptor();
        encryptor2.setPassword(password);
        
        for (int i = 0; i < 100; i++) {
            byte[] encryptedMessage = encryptor.encrypt(messageBytes);
            byte[] decryptedMessage = encryptor2.decrypt(encryptedMessage);
            assertTrue(Arrays.equals(decryptedMessage, messageBytes));
        }
        
    }

}
