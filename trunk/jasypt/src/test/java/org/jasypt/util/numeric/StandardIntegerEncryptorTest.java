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
package org.jasypt.util.numeric;


import java.math.BigInteger;

import junit.framework.TestCase;

public class StandardIntegerEncryptorTest extends TestCase {

    
    
    public void testEncrypt() throws Exception {
        
        BigInteger message = BigInteger.valueOf(-12321318473812923L);
        String password = "A PASSWORD1234";
        
        StandardIntegerEncryptor encryptor = new StandardIntegerEncryptor();
        encryptor.setPassword(password);
        
        for (int i = 0; i < 100; i++) {
            BigInteger encryptedMessage = encryptor.encrypt(message);
            assertTrue(encryptor.decrypt(encryptedMessage).equals(message));
        }
        
        StandardIntegerEncryptor textEncryptor2 = new StandardIntegerEncryptor();
        textEncryptor2.setPassword(password);
        for (int i = 0; i < 100; i++) {
            BigInteger encryptedMessage = encryptor.encrypt(message);
            assertTrue(textEncryptor2.decrypt(encryptedMessage).equals(message));
        }
        
        for (int i = 0; i < 100; i++) {
            assertFalse(encryptor.encrypt(message).equals(
                            encryptor.encrypt(message)));
        }
        
    }

    
}
