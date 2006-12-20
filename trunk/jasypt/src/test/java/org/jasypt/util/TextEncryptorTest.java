package org.jasypt.util;


import junit.framework.TestCase;

import org.apache.commons.codec.binary.Base64;

public class TextEncryptorTest extends TestCase {

    
    
    public void testEncrypt() throws Exception {
        
        String message = "This is a Message";
        String password = "APASSWORD";
        
        TextEncryptor textEncryptor = new TextEncryptor();
        textEncryptor.setPassword(password);
        
        for (int i = 0; i < 100; i++) {
            String encryptedMessage = textEncryptor.encrypt(message);
            assertTrue(Base64.isArrayByteBase64(encryptedMessage.getBytes("US-ASCII")));
            assertEquals(textEncryptor.decrypt(encryptedMessage), message);
        }
        
        TextEncryptor textEncryptor2 = new TextEncryptor();
        textEncryptor2.setPassword(password);
        for (int i = 0; i < 100; i++) {
            String encryptedMessage = textEncryptor.encrypt(message);
            assertTrue(Base64.isArrayByteBase64(encryptedMessage.getBytes("US-ASCII")));
            assertEquals(textEncryptor2.decrypt(encryptedMessage), message);
        }
        
        for (int i = 0; i < 100; i++) {
            assertFalse(
                    textEncryptor.encrypt(message).equals(
                            textEncryptor.encrypt(message)));
        }
        
    }

    
}
