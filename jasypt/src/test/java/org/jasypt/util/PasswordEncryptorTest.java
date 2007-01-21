/*
 * $Source$
 * $Revision$
 * $Date$
 *
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
 */
package org.jasypt.util;


import junit.framework.TestCase;

import org.apache.commons.codec.binary.Base64;
import org.jasypt.util.PasswordEncryptor;

public class PasswordEncryptorTest extends TestCase {

    
    
    public void testDigest() throws Exception {
        
        String password = "This is a Password";
        
        PasswordEncryptor passwordEncryptor = new PasswordEncryptor();
        String encryptedPassword = passwordEncryptor.encryptPassword(password);
        assertTrue(Base64.isArrayByteBase64(encryptedPassword.getBytes("US-ASCII")));
        
        for (int i = 0; i < 100; i++) {
            assertTrue(passwordEncryptor.checkEncryptedPassword(password, encryptedPassword));
        }
        
        String password2 = "This is a  Password";
        for (int i = 0; i < 100; i++) {
            assertFalse(passwordEncryptor.checkEncryptedPassword(password2, encryptedPassword));
        }

        PasswordEncryptor digester2 = new PasswordEncryptor();
        for (int i = 0; i < 100; i++) {
            assertTrue(digester2.checkEncryptedPassword(password, encryptedPassword));
        }
        
        for (int i = 0; i < 100; i++) {
            assertFalse(
                    passwordEncryptor.encryptPassword(password).equals(
                            passwordEncryptor.encryptPassword(password)));
        }
        
        PasswordEncryptor digester3 = new PasswordEncryptor();
        encryptedPassword = digester3.encryptPassword(password);
        
        for (int i = 0; i < 100; i++) {
            assertTrue(digester3.checkEncryptedPassword(password, encryptedPassword));
        }
        
    }

    
}
