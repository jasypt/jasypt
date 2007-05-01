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


import java.security.Security;

import junit.framework.TestCase;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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

        StandardStringDigester digester6 = new StandardStringDigester();
        SimpleDigesterConfig dig6Config = new SimpleDigesterConfig();
        dig6Config.setProvider(new BouncyCastleProvider());
        digester6.setConfig(dig6Config);
        String digest6 = digester6.digest(message);
        
        for (int i = 0; i < 100; i++) {
            assertTrue(digester6.matches(message, digest6));
        }


        Security.addProvider(new BouncyCastleProvider());
        
        StandardStringDigester digester7 = new StandardStringDigester();
        SimpleDigesterConfig dig7Config = new SimpleDigesterConfig();
        dig7Config.setProviderName("BC");
        digester7.setConfig(dig7Config);
        String digest7 = digester7.digest(message);
        
        for (int i = 0; i < 100; i++) {
            assertTrue(digester7.matches(message, digest7));
        }
        
        StandardStringDigester digester8 = new StandardStringDigester();
        SimpleDigesterConfig dig8Config = new SimpleDigesterConfig();
        dig8Config.setProvider(new BouncyCastleProvider());
        dig8Config.setProviderName("SUN");
        dig8Config.setAlgorithm("WHIRLPOOL");
        digester8.setConfig(dig8Config);
        String digest8 = digester8.digest(message);
        
        for (int i = 0; i < 100; i++) {
            assertTrue(digester8.matches(message, digest8));
        }
        
    }
    
}
