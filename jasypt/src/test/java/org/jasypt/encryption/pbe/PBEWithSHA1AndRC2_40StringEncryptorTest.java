package org.jasypt.encryption.pbe;

import junit.framework.TestCase;

import org.jasypt.exceptions.EncryptionOperationNotPossibleException;

public class PBEWithSHA1AndRC2_40StringEncryptorTest extends TestCase {

    public void testEncryptAndDecrypt() throws Exception {

        String password = "A PASSWORD BEING SET";
        String password2 = "A PASSWORD BEING SET ";
        
        String message = "This is a message";
        
        PBEWithSHA1AndRC2_40StringEncryptor encryptor = 
            new PBEWithSHA1AndRC2_40StringEncryptor();
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
        
        PBEWithSHA1AndRC2_40StringEncryptor encryptor2 = 
            new PBEWithSHA1AndRC2_40StringEncryptor();
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
