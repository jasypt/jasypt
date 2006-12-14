package org.jasypt.encryption;

import java.util.Random;

import junit.framework.TestCase;

import org.apache.commons.lang.RandomStringUtils;
import org.jasypt.exceptions.EncryptionInitializationException;

public class PasswordBasedEncryptorTest extends TestCase {

    public void testEncryptAndDecrypt() {
        
        
        Random random = new Random(System.currentTimeMillis());
        
        PasswordBasedEncryptor encryptor = new PasswordBasedEncryptor();
        
        try {
            encryptor.encrypt("");
            assertTrue(false);
        } catch (EncryptionInitializationException e) {
        }
        
        encryptor.setBase64Encoded(true);

        for (int i = 0; i < 5; i++) {
            String password = 
                RandomStringUtils.random(random.nextInt(10000), true, true);
            encryptor.setPassword(password);
            String plainText = "";
            String encryptedText = encryptor.encrypt(plainText);
            assertEquals(encryptor.decrypt(encryptedText), plainText);
            for (int z = 0; z < 5; z++) {
                PasswordBasedEncryptor encryptor2 = 
                    new PasswordBasedEncryptor();
                encryptor2.setPassword(password);
                assertEquals(encryptor2.decrypt(encryptedText), plainText);
            }
            for (int j = 0; j < 100; j++) {
                plainText = 
                    RandomStringUtils.random(random.nextInt(10000), true, true);
                encryptedText = encryptor.encrypt(plainText);
                assertEquals(encryptor.decrypt(encryptedText), plainText);
                for (int z = 0; z < 5; z++) {
                    PasswordBasedEncryptor encryptor2 = 
                        new PasswordBasedEncryptor();
                    encryptor2.setPassword(password);
                    assertEquals(encryptor2.decrypt(encryptedText), plainText);
                }
            }
        }
        
    }

}
