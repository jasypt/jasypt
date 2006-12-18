package org.jasypt.digest;


import java.util.Arrays;

import junit.framework.TestCase;

public class StandardByteDigesterTest extends TestCase {

    
    
    public void testDigest() throws Exception {
        
        String message = "This is a Message";
        byte[] messageBytes = message.getBytes("UTF-8");
        
        StandardByteDigester digester = new StandardByteDigester();
        byte[] digest = digester.digest(messageBytes);
        
        for (int i = 0; i < 100; i++) {
            assertTrue(digester.matches(messageBytes, digest));
        }
        
        String message2 = "This is a  Message";
        byte[] message2Bytes = message2.getBytes("UTF-8");
        for (int i = 0; i < 100; i++) {
            assertFalse(digester.matches(message2Bytes, digest));
        }

        StandardByteDigester digester2 = new StandardByteDigester();
        for (int i = 0; i < 100; i++) {
            assertTrue(digester2.matches(messageBytes, digest));
        }
        
        for (int i = 0; i < 100; i++) {
            assertFalse(Arrays.equals(
                    digester.digest(messageBytes), 
                    digester.digest(messageBytes)));
        }
        
        StandardByteDigester digester3 = new StandardByteDigester();
        digester3.setSaltSizeBytes(0);
        digest = digester3.digest(messageBytes);
        
        for (int i = 0; i < 100; i++) {
            assertTrue(digester3.matches(messageBytes, digest));
        }
        
    }

    
}
