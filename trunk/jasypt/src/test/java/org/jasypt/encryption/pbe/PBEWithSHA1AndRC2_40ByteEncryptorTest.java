package org.jasypt.encryption.pbe;

import java.util.Arrays;

import junit.framework.TestCase;

import org.jasypt.encryption.pbe.PBEWithSHA1AndRC2_40ByteEncryptor;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;

public class PBEWithSHA1AndRC2_40ByteEncryptorTest extends TestCase {

    public void testEncryptAndDecrypt() throws Exception {

        String password = "A PASSWORD BEING SET";
        String password2 = "A PASSWORD BEING SET ";
        
        String message = "This is a message";
        byte[] messageBytes = message.getBytes("UTF-8");
        
        PBEWithSHA1AndRC2_40ByteEncryptor encryptor = 
            new PBEWithSHA1AndRC2_40ByteEncryptor();
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
        
        PBEWithSHA1AndRC2_40ByteEncryptor encryptor2 = 
            new PBEWithSHA1AndRC2_40ByteEncryptor();
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
