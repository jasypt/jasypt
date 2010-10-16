/*
 * =============================================================================
 * 
 *   Copyright (c) 2007-2010, The JASYPT team (http://www.jasypt.org)
 * 
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 * 
 *       http://www.apache.org/licenses/LICENSE-2.0
 * 
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 * 
 * =============================================================================
 */
package org.jasypt.digest;


import java.util.Arrays;

import junit.framework.TestCase;

import org.jasypt.digest.config.SimpleDigesterConfig;
import org.jasypt.salt.FixedByteArraySaltGenerator;
import org.jasypt.salt.FixedStringSaltGenerator;

public class StandardByteDigesterTest extends TestCase {

    
    
    public void testDigest() throws Exception {
        
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
        
        String saltString = "Jasypt Salt Testing";
        byte[] saltByteArray  = saltString.getBytes("UTF-8");
        FixedByteArraySaltGenerator fixedSaltGen = 
            new FixedByteArraySaltGenerator();
        fixedSaltGen.setSalt(saltByteArray);
        FixedStringSaltGenerator fixedStrSaltGen = 
            new FixedStringSaltGenerator();
        fixedStrSaltGen.setSalt(saltString);
        
        StandardByteDigester digester4 = new StandardByteDigester();
        digester4.setSaltGenerator(fixedSaltGen);
        byte[] digest4 = digester4.digest(messageBytes);
        
        StandardByteDigester digester5 = new StandardByteDigester();
        SimpleDigesterConfig dig5Config = new SimpleDigesterConfig();
        dig5Config.setSaltGenerator(fixedStrSaltGen);
        digester5.setConfig(dig5Config);
        byte[] digest5 = digester5.digest(messageBytes);
        
        for (int i = 0; i < 100; i++) {
            assertTrue(digester4.matches(messageBytes, digest4));
        }
        
        for (int i = 0; i < 100; i++) {
            assertTrue(digester5.matches(messageBytes, digest5));
        }
        
        for (int i = 0; i < 100; i++) {
            assertTrue(Arrays.equals(
                    digester4.digest(messageBytes),
                    digester5.digest(messageBytes)));
        }
        
    }

    
}
