package org.jasypt.digest;


import java.util.Arrays;

import junit.framework.TestCase;

import org.jasypt.digest.config.SimpleDigesterConfig;

public class StandardByteDigesterTest extends TestCase {

    
    
    public void testDigest() throws Exception {

        StandardByteDigester digesterWithConfig = new StandardByteDigester();
        SimpleDigesterConfig config = new SimpleDigesterConfig();
        config.setAlgorithm("SHA-1");
        config.setIterations(new Integer(50000));
        digesterWithConfig.setConfig(config);
        assertEquals("SHA-1", digesterWithConfig.getAlgorithm());
        assertEquals(50000, digesterWithConfig.getIterations());
        digesterWithConfig.setAlgorithm("MD5");
        assertEquals("MD5", digesterWithConfig.getAlgorithm());
        assertEquals(50000, digesterWithConfig.getIterations());
        
        String message = "This is a Message";
        byte[] messageBytes = message.getBytes("UTF-8");
        
        StandardByteDigester digester = new StandardByteDigester();
        
        assertTrue(digester.digest(null) == null);
        assertTrue(digester.digest(new byte[0]) != null);
        
        byte[] digestOfEmpty = digester.digest(new byte[0]);
        assertTrue(digester.matches(new byte[0], digestOfEmpty));

        assertTrue(digester.matches(null, null));
        assertFalse(digester.matches(null, new byte[0]));
        assertFalse(digester.matches(new byte[0], null));
        
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
