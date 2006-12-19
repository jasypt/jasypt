package org.jasypt.pbe;

import java.util.Arrays;

import org.jasypt.exceptions.EncryptionOperationNotPossibleException;

import junit.framework.TestCase;

public class PBEWithMD5AndDESByteEncryptorTest extends TestCase {

    public void testEncryptAndDecrypt() throws Exception {

        String password = "A PASSWORD BEING SET";
        String password2 = "A PASSWORD BEING SET ";
        
        String message = "This is a message";
        byte[] messageBytes = message.getBytes("UTF-8");
        
        PBEWithMD5AndDESByteEncryptor encryptor = 
            new PBEWithMD5AndDESByteEncryptor();
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
        
        PBEWithMD5AndDESByteEncryptor encryptor2 = 
            new PBEWithMD5AndDESByteEncryptor();
        encryptor2.setPassword(password);
        
        for (int i = 0; i < 100; i++) {
            byte[] encryptedMessage = encryptor.encrypt(messageBytes);
            byte[] decryptedMessage = encryptor2.decrypt(encryptedMessage);
            assertTrue(Arrays.equals(decryptedMessage, messageBytes));
        }
        
        encryptor2.setPassword(password2);
        
        for (int i = 0; i < 100; i++) {
            byte[] encryptedMessage = encryptor.encrypt(messageBytes);
            try {
                byte[] decryptedMessage = encryptor2.decrypt(encryptedMessage);
                assertFalse(Arrays.equals(decryptedMessage, messageBytes));
            } catch (EncryptionOperationNotPossibleException e) {
                assertTrue(true);
            }
        }
    }

}
