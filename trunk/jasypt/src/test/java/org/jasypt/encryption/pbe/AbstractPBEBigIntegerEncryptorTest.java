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

import java.math.BigInteger;

import junit.framework.TestCase;

import org.jasypt.exceptions.EncryptionOperationNotPossibleException;

public abstract class AbstractPBEBigIntegerEncryptorTest extends TestCase {

    public void testEncryptAndDecrypt() throws Exception {

        String password = "A PASSWORD BEING SET";
        String password2 = "A PASSWORD BEING SET ";
        
        BigInteger message = BigInteger.valueOf(-123534452L);

        PBEBigIntegerEncryptor encryptor = createPBEIntegerEncryptor();
        encryptor.setPassword(password);
        
        assertTrue(encryptor.encrypt(null) == null);
        assertTrue(encryptor.decrypt(null) == null);
        
        BigInteger encryptOfEmpty = encryptor.encrypt(BigInteger.valueOf(0));
        assertTrue(encryptor.decrypt(encryptOfEmpty).equals(BigInteger.valueOf(0)));
        
        for (int i = 0; i < 100; i++) {
            BigInteger encryptedMessage = encryptor.encrypt(message);
            BigInteger decryptedMessage = encryptor.decrypt(encryptedMessage);
            assertEquals(decryptedMessage, message);
        }
        
        for (int i = 0; i < 100; i++) {
            assertFalse(
                        encryptor.encrypt(message).equals(
                        encryptor.encrypt(message)));
        }
        
        PBEBigIntegerEncryptor encryptor2 = createPBEIntegerEncryptor();
        encryptor2.setPassword(password);

        assertEquals(encryptor2.decrypt(encryptOfEmpty),BigInteger.valueOf(0));
        
        for (int i = 0; i < 100; i++) {
            BigInteger encryptedMessage = encryptor.encrypt(message);
            BigInteger decryptedMessage = encryptor2.decrypt(encryptedMessage);
            assertEquals(decryptedMessage, message);
        }
        
        PBEBigIntegerEncryptor encryptor3 = createPBEIntegerEncryptor();
        encryptor3.setPassword(password2);
        
        for (int i = 0; i < 100; i++) {
            BigInteger encryptedMessage = encryptor.encrypt(message);
            try {
                BigInteger decryptedMessage = encryptor3.decrypt(encryptedMessage);
                assertFalse(message.equals(decryptedMessage));
            } catch (EncryptionOperationNotPossibleException e) {
                assertTrue(true);
            }
        }
        
        
    }

    
    protected abstract PBEBigIntegerEncryptor createPBEIntegerEncryptor();
    
}
