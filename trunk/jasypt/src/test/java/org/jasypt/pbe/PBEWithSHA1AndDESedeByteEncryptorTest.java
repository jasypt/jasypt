package org.jasypt.pbe;

import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Iterator;

import org.jasypt.exceptions.EncryptionOperationNotPossibleException;

import junit.framework.TestCase;

public class PBEWithSHA1AndDESedeByteEncryptorTest extends TestCase {

    public void testEncryptAndDecrypt() throws Exception {

        Provider[] providers = Security.getProviders();
        for (int i = 0; i < providers.length; i++) {
          System.out.println( "Provider: " + providers[ i ].getName() + ", " + providers[ i ].getInfo() );
             for( Iterator itr = providers[i].keySet().iterator(); itr.hasNext(); ) {
               String key = ( String )itr.next();
               String value = ( String )providers[ i ].get( key );
               System.out.println( "\t" + key + " = " + value );
             }
        }
        
        
        String password = "A PASSWORD BEING SET";
        String password2 = "A PASSWORD BEING SET ";
        
        String message = "This is a message";
        byte[] messageBytes = message.getBytes("UTF-8");
        
        PBEWithSHA1AndDESedeByteEncryptor encryptor = 
            new PBEWithSHA1AndDESedeByteEncryptor();
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
        
        PBEWithSHA1AndDESedeByteEncryptor encryptor2 = 
            new PBEWithSHA1AndDESedeByteEncryptor();
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
