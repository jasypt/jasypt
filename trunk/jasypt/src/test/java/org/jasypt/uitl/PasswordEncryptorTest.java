package org.jasypt.uitl;


import junit.framework.TestCase;

import org.apache.commons.codec.binary.Base64;
import org.jasypt.util.PasswordEncryptor;

public class PasswordEncryptorTest extends TestCase {

    
    
    public void testDigest() throws Exception {
        
        String password = "This is a Password";
        
        PasswordEncryptor passwordEncryptor = new PasswordEncryptor();
        String encryptedPassword = passwordEncryptor.encryptPassword(password);
        assertTrue(Base64.isArrayByteBase64(encryptedPassword.getBytes("US-ASCII")));
        
        for (int i = 0; i < 100; i++) {
            assertTrue(passwordEncryptor.checkEncryptedPassword(password, encryptedPassword));
        }
        
        String password2 = "This is a  Password";
        for (int i = 0; i < 100; i++) {
            assertFalse(passwordEncryptor.checkEncryptedPassword(password2, encryptedPassword));
        }

        PasswordEncryptor digester2 = new PasswordEncryptor();
        for (int i = 0; i < 100; i++) {
            assertTrue(digester2.checkEncryptedPassword(password, encryptedPassword));
        }
        
        for (int i = 0; i < 100; i++) {
            assertFalse(
                    passwordEncryptor.encryptPassword(password).equals(
                            passwordEncryptor.encryptPassword(password)));
        }
        
        PasswordEncryptor digester3 = new PasswordEncryptor();
        encryptedPassword = digester3.encryptPassword(password);
        
        for (int i = 0; i < 100; i++) {
            assertTrue(digester3.checkEncryptedPassword(password, encryptedPassword));
        }
        
    }

    
}
