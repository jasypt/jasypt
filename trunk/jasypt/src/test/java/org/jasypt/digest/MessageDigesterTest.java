package org.jasypt.digest;


import java.util.Random;

import junit.framework.TestCase;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.RandomStringUtils;

public class MessageDigesterTest extends TestCase {

    
    
    public void testDigest() throws Exception {
        
        Random random = new Random(System.currentTimeMillis());
        
        MessageDigester digester = new MessageDigester();
        
        digester.setBase64Encoded(true);
        for (int i = 0; i < 10; i++) {
            MessageDigester varDigester = new MessageDigester();
            varDigester.setBase64Encoded(true);
            assertEquals(digester.digest(""), varDigester.digest(""));
            for (int j = 0; j < 100; j++) {
                String randomString = RandomStringUtils.random(random.nextInt(10000), true, true);
                String firstDigestion = digester.digest(randomString);
                assertTrue(Base64.isArrayByteBase64(firstDigestion.getBytes()));
                for (int z = 0; z < 5; z++) {
                    assertEquals(firstDigestion, varDigester.digest(randomString));
                }
            }
        }
        
        digester.setBase64Encoded(false);
        for (int i = 0; i < 10; i++) {
            MessageDigester varDigester = new MessageDigester();
            varDigester.setBase64Encoded(false);
            assertEquals(digester.digest(""), varDigester.digest(""));
            for (int j = 0; j < 100; j++) {
                String randomString = RandomStringUtils.random(random.nextInt(10000));
                String firstDigestion = digester.digest(randomString);
                for (int z = 0; z < 5; z++) {
                    assertEquals(firstDigestion, varDigester.digest(randomString));
                }
            }
        }

        digester.setBase64Encoded(true);
        digester.setAlgorithm("SHA");
        for (int i = 0; i < 10; i++) {
            MessageDigester varDigester = new MessageDigester();
            varDigester.setBase64Encoded(true);
            varDigester.setAlgorithm("SHA");
            assertEquals(digester.digest(""), varDigester.digest(""));
            for (int j = 0; j < 100; j++) {
                String randomString = RandomStringUtils.random(random.nextInt(10000));
                String firstDigestion = digester.digest(randomString);
                assertTrue(Base64.isArrayByteBase64(firstDigestion.getBytes()));
                for (int z = 0; z < 5; z++) {
                    assertEquals(firstDigestion, varDigester.digest(randomString));
                }
            }
        }
        
        
    }

    
}
