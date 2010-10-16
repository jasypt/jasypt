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


import java.security.Security;

import junit.framework.TestCase;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jasypt.contrib.org.apache.commons.codec_1_3.binary.Base64;
import org.jasypt.digest.config.EnvironmentStringDigesterConfig;
import org.jasypt.digest.config.SimpleDigesterConfig;
import org.jasypt.salt.RandomSaltGenerator;

public class StandardStringDigesterInvertedSaltTest extends TestCase {

    
    class InvertedRandomSaltGenerator extends RandomSaltGenerator {

        public InvertedRandomSaltGenerator() {
            super();
        }

        public InvertedRandomSaltGenerator(String secureRandomAlgorithm) {
            super(secureRandomAlgorithm);
        }

        public boolean invertPositionOfPlainSaltInEncryptionResults() {
            return true;
        }
        
    }
    
    
    
    public void testDigest() throws Exception {
        
        String message = "This is a Message";
        
        StandardStringDigester digester = new StandardStringDigester();
        digester.setSaltGenerator(new InvertedRandomSaltGenerator());
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
        digester2.setSaltGenerator(new InvertedRandomSaltGenerator());
        for (int i = 0; i < 100; i++) {
            assertTrue(digester2.matches(message, digest));
        }
        
        for (int i = 0; i < 100; i++) {
            assertFalse(digester.digest(message).equals(digester.digest(message)));
        }
        
        StandardStringDigester digester3 = new StandardStringDigester();
        digester3.setSaltGenerator(new InvertedRandomSaltGenerator());
        digester3.setSaltSizeBytes(0);
        digest = digester3.digest(message);
        
        for (int i = 0; i < 100; i++) {
            assertTrue(digester3.matches(message, digest));
        }

        StandardStringDigester digester6 = new StandardStringDigester();
        digester6.setSaltGenerator(new InvertedRandomSaltGenerator());
        SimpleDigesterConfig dig6Config = new SimpleDigesterConfig();
        dig6Config.setProvider(new BouncyCastleProvider());
        digester6.setConfig(dig6Config);
        String digest6 = digester6.digest(message);
        
        for (int i = 0; i < 100; i++) {
            assertTrue(digester6.matches(message, digest6));
        }


        Security.addProvider(new BouncyCastleProvider());
        
        StandardStringDigester digester7 = new StandardStringDigester();
        digester7.setSaltGenerator(new InvertedRandomSaltGenerator());
        SimpleDigesterConfig dig7Config = new SimpleDigesterConfig();
        dig7Config.setProviderName("BC");
        digester7.setConfig(dig7Config);
        String digest7 = digester7.digest(message);
        
        for (int i = 0; i < 100; i++) {
            assertTrue(digester7.matches(message, digest7));
        }
        
        StandardStringDigester digester8 = new StandardStringDigester();
        digester8.setSaltGenerator(new InvertedRandomSaltGenerator());
        SimpleDigesterConfig dig8Config = new SimpleDigesterConfig();
        dig8Config.setProvider(new BouncyCastleProvider());
        dig8Config.setProviderName("SUN");
        dig8Config.setAlgorithm("WHIRLPOOL");
        digester8.setConfig(dig8Config);
        String digest8 = digester8.digest(message);
        
        for (int i = 0; i < 100; i++) {
            assertTrue(digester8.matches(message, digest8));
        }
        
        StandardStringDigester digester9 = new StandardStringDigester();
        digester9.setSaltGenerator(new InvertedRandomSaltGenerator());
        EnvironmentStringDigesterConfig dig9Config = new EnvironmentStringDigesterConfig();
        dig9Config.setProvider(new BouncyCastleProvider());
        dig9Config.setAlgorithm("WHIRLPOOL");
        digester9.setConfig(dig9Config);
        
        String unicodeUncombinedPassword = "A\u0300";
        String unicodeCombinedPassword = "\u00c0";
        
        String unicodeCombinedDigest = digester9.digest(unicodeCombinedPassword);
        assertTrue(digester9.matches(unicodeUncombinedPassword, unicodeCombinedDigest));
        
        String unicodeUncombinedDigest = digester9.digest(unicodeUncombinedPassword);
        assertTrue(digester9.matches(unicodeCombinedPassword, unicodeUncombinedDigest));
        
    }
    
}
