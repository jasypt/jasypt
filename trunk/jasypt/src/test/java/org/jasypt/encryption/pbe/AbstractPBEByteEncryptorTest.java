package org.jasypt.encryption.pbe;

import java.util.Arrays;

import junit.framework.TestCase;

import org.jasypt.exceptions.EncryptionOperationNotPossibleException;

public abstract class AbstractPBEByteEncryptorTest extends TestCase {

    public void testEncryptAndDecrypt() throws Exception {

        String password = "A PASSWORD BEING SET";
        String password2 = "A PASSWORD BEING SET ";
        
        String message = "This is a message";
        byte[] messageBytes = message.getBytes("UTF-8");
        
        PBEByteEncryptor encryptor = createPBEByteEncryptor();
        encryptor.setPassword(password);
        
        assertTrue(encryptor.encrypt(null) == null);
        assertTrue(encryptor.decrypt(null) == null);
        
        assertTrue(encryptor.encrypt(new byte[0]) != null);
        
        byte[] encryptOfEmpty = encryptor.encrypt(new byte[0]);
        assertTrue(Arrays.equals(encryptor.decrypt(encryptOfEmpty), new byte[0]));
        
        
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
        
        PBEByteEncryptor encryptor2 = createPBEByteEncryptor();
        encryptor2.setPassword(password);

        assertTrue(Arrays.equals(encryptor2.decrypt(encryptOfEmpty), new byte[0]));
        
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

    
    protected abstract PBEByteEncryptor createPBEByteEncryptor();
    
}
