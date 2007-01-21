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
package org.jasypt.salt;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.jasypt.exceptions.EncryptionInitializationException;

public final class SaltGeneration {
    
    private static String SECURE_RANDOM_ALGORITHM = "SHA1PRNG";
    private static SecureRandom random = null;
    
    
    static {
        try {
            random = SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM);
            random.setSeed(System.currentTimeMillis());
        } catch (NoSuchAlgorithmException e) {
            throw new EncryptionInitializationException(e);
        }
    }
    
    
    public static byte[] generateSalt(int lengthBytes) {
        byte[] salt = new byte[lengthBytes];
        synchronized (random) {
            random.nextBytes(salt);
        }
        return salt;
    }
    
    
    private SaltGeneration() {}
    
}
