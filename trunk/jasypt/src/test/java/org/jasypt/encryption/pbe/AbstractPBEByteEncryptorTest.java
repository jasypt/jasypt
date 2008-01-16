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
package org.jasypt.encryption.pbe;

import java.util.Arrays;

import junit.framework.TestCase;

import org.jasypt.encryption.pbe.config.SimplePBEConfig;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.jasypt.salt.FixedStringSaltGenerator;

public abstract class AbstractPBEByteEncryptorTest extends TestCase {

    public void testEncryptAndDecrypt() throws Exception {

        String password = "A PASSWORD BEING SET";
        String password2 = "A PASSWORD BEING SET ";
        
        String message = "This is a message";
        byte[] messageBytes = message.getBytes("UTF-8");
        
        PBEByteEncryptor encryptor = createPBEByteEncryptor();
        encryptor.setPassword(password);
        
        assertTrue(encryptor.encrypt(null) == null);
        assertTrue(encryptor.decrypt(null) == null);
        
        assertTrue(encryptor.encrypt(new byte[0]) != null);
        
        byte[] encryptOfEmpty = encryptor.encrypt(new byte[0]);
        assertTrue(Arrays.equals(encryptor.decrypt(encryptOfEmpty), new byte[0]));
        
        
        for (int i = 0; i < 100; i++) {
            byte[] encryptedMessage = encryptor.encrypt(messageBytes);
            byte[] decryptedMessage = encryptor.decrypt(encryptedMessage);
            assertTrue(Arrays.equals(decryptedMessage, messageBytes));
        }
        
        for (int i = 0; i < 100; i++) {
            assertFalse(
                    Arrays.equals(
                            encryptor.encrypt(messageBytes),
                            encryptor.encrypt(messageBytes)));
        }
        
        PBEByteEncryptor encryptor2 = createPBEByteEncryptor();
        encryptor2.setPassword(password);

        assertTrue(Arrays.equals(encryptor2.decrypt(encryptOfEmpty), new byte[0]));
        
        for (int i = 0; i < 100; i++) {
            byte[] encryptedMessage = encryptor.encrypt(messageBytes);
            byte[] decryptedMessage = encryptor2.decrypt(encryptedMessage);
            assertTrue(Arrays.equals(decryptedMessage, messageBytes));
        }
        
        PBEByteEncryptor encryptor3 = createPBEByteEncryptor();
        encryptor3.setPassword(password2);
        
        for (int i = 0; i < 100; i++) {
            byte[] encryptedMessage = encryptor.encrypt(messageBytes);
            try {
                byte[] decryptedMessage = encryptor3.decrypt(encryptedMessage);
                assertFalse(Arrays.equals(decryptedMessage, messageBytes));
            } catch (EncryptionOperationNotPossibleException e) {
                assertTrue(true);
            }
        }
        
        FixedStringSaltGenerator saltGenerator = new FixedStringSaltGenerator();
        saltGenerator.setSalt("Jasypt salting test");
        
        StandardPBEByteEncryptor encryptor4 = createPBEByteEncryptor();
        encryptor4.setPassword(password2);
        encryptor4.setSaltGenerator(saltGenerator);
        byte[] enc4 = encryptor4.encrypt(messageBytes);
        assertTrue(Arrays.equals(encryptor4.decrypt(enc4), messageBytes));
        
        StandardPBEByteEncryptor encryptor5 = createPBEByteEncryptor();
        SimplePBEConfig simplePBEConfig = new SimplePBEConfig();
        simplePBEConfig.setSaltGenerator(saltGenerator);
        encryptor5.setConfig(simplePBEConfig);
        encryptor5.setPassword(password2);
        byte[] enc5 = encryptor5.encrypt(messageBytes);
        assertTrue(Arrays.equals(encryptor5.decrypt(enc4), messageBytes));
        assertTrue(Arrays.equals(encryptor5.decrypt(enc5), messageBytes));
        
        for (int i = 0; i < 100; i++) {
            assertTrue(
                    Arrays.equals(
                            encryptor4.encrypt(messageBytes),
                            encryptor5.encrypt(messageBytes))
                    );
        }

    }

    
    protected abstract StandardPBEByteEncryptor createPBEByteEncryptor();
    
}
