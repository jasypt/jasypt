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


import junit.framework.TestCase;

import org.jasypt.contrib.org.apache.commons.codec_1_3.binary.Base64;
import org.jasypt.util.password.rfc2307.RFC2307SSHAPasswordEncryptor;

public class StandardStringDigesterInvertedSaltTest extends TestCase {
    
    
    
    public void testDigest() throws Exception {
        
        String message = "This is a Message";
        
        StandardStringDigester digester = new StandardStringDigester();
        digester.setInvertPositionOfPlainSaltInEncryptionResults(true);
        digester.setInvertPositionOfSaltInMessageBeforeDigesting(true);
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
        digester2.setInvertPositionOfPlainSaltInEncryptionResults(true);
        digester2.setInvertPositionOfSaltInMessageBeforeDigesting(true);
        for (int i = 0; i < 100; i++) {
            assertTrue(digester2.matches(message, digest));
        }

        
        StandardStringDigester digester3 = new StandardStringDigester();
        digester3.setAlgorithm("SHA-1");
        digester3.setIterations(1);
        digester3.setSaltSizeBytes(4);
        digester3.setPrefix("{SSHA}");
        digester3.setInvertPositionOfSaltInMessageBeforeDigesting(true);
        digester3.setInvertPositionOfPlainSaltInEncryptionResults(true);
        digester3.setUseLenientSaltSizeCheck(true);
        
        assertTrue(digester3.matches("secret", "{SSHA}cOkpWg5OyRXUEWt+Y/jbEU8/QZfx1hBL17TIBA=="));

        RFC2307SSHAPasswordEncryptor ssha = new RFC2307SSHAPasswordEncryptor();
        ssha.setSaltSizeBytes(4);
        final String encSSHA = ssha.encryptPassword("secret");
        
        assertTrue(ssha.checkPassword("secret", "{SSHA}cOkpWg5OyRXUEWt+Y/jbEU8/QZfx1hBL17TIBA=="));
        assertTrue(ssha.checkPassword("secret", encSSHA));
        
    }
    
}
