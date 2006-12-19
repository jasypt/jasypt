package org.jasypt.encryption.pbe;

import java.util.Arrays;

import org.jasypt.encryption.pbe.PBEWithMD5AndTripleDESByteEncryptor;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;

import junit.framework.TestCase;

public class PBEWithMD5AndTripleDESByteEncryptorTest extends TestCase {

    public void testEncryptAndDecrypt() throws Exception {

        String password = "A PASSWORD BEING SET";
        String password2 = "A PASSWORD BEING SET ";
        
        String message = "This is a message";
        byte[] messageBytes = message.getBytes("UTF-8");
        
        PBEWithMD5AndTripleDESByteEncryptor encryptor = 
            new PBEWithMD5AndTripleDESByteEncryptor();
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
        
        PBEWithMD5AndTripleDESByteEncryptor encryptor2 = 
            new PBEWithMD5AndTripleDESByteEncryptor();
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
