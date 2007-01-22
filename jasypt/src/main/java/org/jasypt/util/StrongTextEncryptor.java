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
package org.jasypt.util;

import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.encryption.pbe.algorithms.PBEAlgorithms;

public final class StrongTextEncryptor implements TextEncryptor {

    
    private StandardPBEStringEncryptor encryptor = null;
    
    
    public StrongTextEncryptor() {
        this.encryptor = new StandardPBEStringEncryptor();
        this.encryptor.setAlgorithm(PBEAlgorithms.PBE_WITH_MD5_AND_TRIPLE_DES);
    }
    
    public void setPassword(String password) {
        encryptor.setPassword(password);
    }

    
    public String encrypt(String message) {
        return encryptor.encrypt(message);
    }
    
    public String decrypt(String encryptedMessage) {
        return encryptor.decrypt(encryptedMessage);
    }
    
}
