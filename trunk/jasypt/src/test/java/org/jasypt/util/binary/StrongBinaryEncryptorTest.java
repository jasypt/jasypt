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
package org.jasypt.util.binary;


import java.util.Arrays;

import junit.framework.TestCase;

public class StrongBinaryEncryptorTest extends TestCase {

    
    
    public void testEncrypt() throws Exception {
        
        byte[] message = "This is a Message".getBytes();
        String password = "APASSWORD";
        
        StrongBinaryEncryptor textEncryptor = new StrongBinaryEncryptor();
        textEncryptor.setPassword(password);
        
        for (int i = 0; i < 100; i++) {
            byte[] encryptedMessage = textEncryptor.encrypt(message);
            assertTrue(Arrays.equals(textEncryptor.decrypt(encryptedMessage), message));
        }
        
        StrongBinaryEncryptor textEncryptor2 = new StrongBinaryEncryptor();
        textEncryptor2.setPassword(password);
        for (int i = 0; i < 100; i++) {
            byte[] encryptedMessage = textEncryptor.encrypt(message);
            assertTrue(Arrays.equals(textEncryptor2.decrypt(encryptedMessage), message));
        }
        
        for (int i = 0; i < 100; i++) {
            assertFalse(Arrays.equals(
                    textEncryptor.encrypt(message),
                            textEncryptor.encrypt(message)));
        }
        
    }

    
}
