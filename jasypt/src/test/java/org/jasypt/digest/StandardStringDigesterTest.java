package org.jasypt.digest;


import junit.framework.TestCase;

import org.apache.commons.codec.binary.Base64;

public class StandardStringDigesterTest extends TestCase {

    
    
    public void testDigest() throws Exception {
        
        String message = "This is a Message";
        
        StandardStringDigester digester = new StandardStringDigester();
        String digest = digester.digest(message);
        
        assertTrue(digester.digest(null) == null);
        assertTrue(digester.digest("") != null);
        
        String digestOfEmpty = digester.digest("");
        assertTrue(digester.matches("", digestOfEmpty));

        assertTrue(digester.matches(null, null));
        assertFalse(digester.matches(null, ""));
        assertFalse(digester.matches("", null));

        assertTrue(digester.matches(null, null));
        
        assertTrue(Base64.isArrayByteBase64(digest.getBytes("US-ASCII")));
        
        for (int i = 0; i < 100; i++) {
            assertTrue(digester.matches(message, digest));
        }
        
        String message2 = "This is a  Message";
        for (int i = 0; i < 100; i++) {
            assertFalse(digester.matches(message2, digest));
        }

        StandardStringDigester digester2 = new StandardStringDigester();
        for (int i = 0; i < 100; i++) {
            assertTrue(digester2.matches(message, digest));
        }
        
        for (int i = 0; i < 100; i++) {
            assertFalse(digester.digest(message).equals(digester.digest(message)));
        }
        
        StandardStringDigester digester3 = new StandardStringDigester();
        digester3.setSaltSizeBytes(0);
        digest = digester3.digest(message);
        
        for (int i = 0; i < 100; i++) {
            assertTrue(digester3.matches(message, digest));
        }
        
    }

    
}
