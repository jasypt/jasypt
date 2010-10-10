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
package org.jasypt.util.password;


import java.security.Security;

import junit.framework.TestCase;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jasypt.contrib.org.apache.commons.codec_1_3.binary.Base64;

public class ConfigurablePasswordEncryptorTest extends TestCase {

    
    
    public void testDigest() throws Exception {

        String password = "This is a Password";
        
        ConfigurablePasswordEncryptor passwordEncryptor = new ConfigurablePasswordEncryptor();
        passwordEncryptor.setAlgorithm("WHIRLPOOL");
        passwordEncryptor.setProvider(new BouncyCastleProvider());
        
        String encryptedPassword = passwordEncryptor.encryptPassword(password);
        assertTrue(Base64.isArrayByteBase64(encryptedPassword.getBytes("US-ASCII")));
        
        for (int i = 0; i < 10; i++) {
            assertTrue(passwordEncryptor.checkPassword(password, encryptedPassword));
        }
        
        String password2 = "This is a  Password";
        for (int i = 0; i < 10; i++) {
            assertFalse(passwordEncryptor.checkPassword(password2, encryptedPassword));
        }

        ConfigurablePasswordEncryptor digester2 = new ConfigurablePasswordEncryptor();
        digester2.setAlgorithm("WHIRLPOOL");
        Security.addProvider(new BouncyCastleProvider());
        digester2.setProviderName("BC");
        
        for (int i = 0; i < 10; i++) {
            assertTrue(digester2.checkPassword(password, encryptedPassword));
        }
        
        for (int i = 0; i < 10; i++) {
            assertFalse(
                    passwordEncryptor.encryptPassword(password).equals(
                            passwordEncryptor.encryptPassword(password)));
        }
        
        StrongPasswordEncryptor digester3 = new StrongPasswordEncryptor();
        encryptedPassword = digester3.encryptPassword(password);
        
        for (int i = 0; i < 10; i++) {
            assertTrue(digester3.checkPassword(password, encryptedPassword));
        }
        
    }

    
}
