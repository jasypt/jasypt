package org.jasypt.encryption.pbe;

import junit.framework.TestCase;

import org.jasypt.exceptions.EncryptionOperationNotPossibleException;

public class PBEWithMD5AndTripleDESStringEncryptorTest extends TestCase {

    public void testEncryptAndDecrypt() throws Exception {

        String password = "A PASSWORD BEING SET";
        String password2 = "A PASSWORD BEING SET ";
        
        String message = "This is a message";
        
        PBEWithMD5AndTripleDESStringEncryptor encryptor = 
            new PBEWithMD5AndTripleDESStringEncryptor();
        encryptor.setPassword(password);
        
        for (int i = 0; i < 100; i++) {
            String encryptedMessage = encryptor.encrypt(message);
            String decryptedMessage = encryptor.decrypt(encryptedMessage);
            assertEquals(decryptedMessage, message);
        }
        
        for (int i = 0; i < 100; i++) {
            assertFalse(
                encryptor.encrypt(message).equals(
                encryptor.encrypt(message)));
        }
        
        PBEWithMD5AndTripleDESStringEncryptor encryptor2 = 
            new PBEWithMD5AndTripleDESStringEncryptor();
        encryptor2.setPassword(password);
        
        for (int i = 0; i < 100; i++) {
            String encryptedMessage = encryptor.encrypt(message);
            String decryptedMessage = encryptor2.decrypt(encryptedMessage);
            assertEquals(decryptedMessage, message);
        }
        
        encryptor2.setPassword(password2);
        
        for (int i = 0; i < 100; i++) {
            String encryptedMessage = encryptor.encrypt(message);
            try {
                String decryptedMessage = encryptor2.decrypt(encryptedMessage);
                assertFalse(message.equals(decryptedMessage));
            } catch (EncryptionOperationNotPossibleException e) {
                assertTrue(true);
            }
        }
    }

}
