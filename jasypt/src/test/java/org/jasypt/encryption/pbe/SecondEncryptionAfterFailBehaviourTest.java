package org.jasypt.encryption.pbe;

import junit.framework.TestCase;

public class SecondEncryptionAfterFailBehaviourTest extends TestCase {

    
    
    public void testSecondEncryptionAfterFailBehaviour() throws Exception {

        String vsessionid = "012345678";
        StandardPBEStringEncryptor strongEncryptor = 
            new StandardPBEStringEncryptor();
        strongEncryptor.setPassword("jasypt");

        try {
                strongEncryptor.decrypt(vsessionid);
        } catch (Exception ignored) {
            // This exception will be always thrown, but ignored
        }
        String enc = strongEncryptor.encrypt(vsessionid);
        try {
            strongEncryptor.decrypt(enc);
        } catch (Exception e) {           
            assertTrue(false);
        }
        
    }
}
