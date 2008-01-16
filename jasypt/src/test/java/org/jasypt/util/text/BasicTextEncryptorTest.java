/*
 * =============================================================================
 * 
 *   Copyright (c) 2007-2008, The JASYPT team (http://www.jasypt.org)
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
package org.jasypt.util.text;


import junit.framework.TestCase;

import org.apache.commons.codec.binary.Base64;

public class BasicTextEncryptorTest extends TestCase {

    
    
    public void testEncrypt() throws Exception {
        
        String message = "This is a Message";
        String password = "APASSWORD";
        
        BasicTextEncryptor textEncryptor = new BasicTextEncryptor();
        textEncryptor.setPassword(password);
        
        for (int i = 0; i < 100; i++) {
            String encryptedMessage = textEncryptor.encrypt(message);
            assertTrue(Base64.isArrayByteBase64(encryptedMessage.getBytes("US-ASCII")));
            assertEquals(textEncryptor.decrypt(encryptedMessage), message);
        }
        
        BasicTextEncryptor textEncryptor2 = new BasicTextEncryptor();
        textEncryptor2.setPassword(password);
        for (int i = 0; i < 100; i++) {
            String encryptedMessage = textEncryptor.encrypt(message);
            assertTrue(Base64.isArrayByteBase64(encryptedMessage.getBytes("US-ASCII")));
            assertEquals(textEncryptor2.decrypt(encryptedMessage), message);
        }
        
        for (int i = 0; i < 100; i++) {
            assertFalse(
                    textEncryptor.encrypt(message).equals(
                            textEncryptor.encrypt(message)));
        }
        
    }

    
}
