/*
 * =============================================================================
 * 
 *   Copyright (c) 2007, The JASYPT team (http://www.jasypt.org)
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


import junit.framework.TestCase;

import org.apache.commons.codec.binary.Base64;
import org.jasypt.digest.config.SimpleDigesterConfig;
import org.jasypt.salt.FixedByteArraySaltGenerator;

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
        
        String saltString = "Jasypt Salt Testing";
        byte[] saltByteArray  = saltString.getBytes("UTF-8");
        FixedByteArraySaltGenerator fixedSaltGen = 
            new FixedByteArraySaltGenerator();
        fixedSaltGen.setSalt(saltByteArray);

        StandardStringDigester digester4 = new StandardStringDigester();
        digester4.setSaltGenerator(fixedSaltGen);
        String digest4 = digester4.digest(message);
        
        for (int i = 0; i < 100; i++) {
            assertTrue(digester4.matches(message, digest4));
        }

        StandardStringDigester digester5 = new StandardStringDigester();
        SimpleDigesterConfig dig5Config = new SimpleDigesterConfig();
        dig5Config.setSaltGenerator(fixedSaltGen);
        digester5.setConfig(dig5Config);
        String digest5 = digester5.digest(message);
        
        for (int i = 0; i < 100; i++) {
            assertTrue(digester5.matches(message, digest5));
        }

        
        for (int i = 0; i < 100; i++) {
            assertTrue(
                    digester4.digest(message).equals(
                    digester5.digest(message)));
        }
        
    }
    
}
