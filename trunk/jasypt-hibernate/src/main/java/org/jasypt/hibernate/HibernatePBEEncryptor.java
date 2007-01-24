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
package org.jasypt.hibernate;

import org.jasypt.encryption.pbe.PBEStringEncryptor;
import org.jasypt.exceptions.EncryptionInitializationException;

public class HibernatePBEEncryptor {


    private String name = null;
    private PBEStringEncryptor encryptor = null;
    
    
    
    public HibernatePBEEncryptor() {
    }

    
    HibernatePBEEncryptor(String name, PBEStringEncryptor encryptor) {
        this.name = name;
        this.encryptor = encryptor;
    }

    
    public void setName(String name) {
        if (this.name != null) {
            HibernatePBEEncryptorRegistry.getInstance().
                    unregisterHibernatePBEEncryptor(this.name);
        }
        this.name = name;
        HibernatePBEEncryptorRegistry.getInstance().
                registerHibernatePBEEncryptor(this);
        
    }
    
    public String getName() {
        return name;
    }
    
    
    public void setEncryptor(PBEStringEncryptor encryptor) {
        this.encryptor = encryptor;
    }

    
    public String encrypt(String message) {
        if (this.encryptor == null) {
            throw new EncryptionInitializationException(
                    "Encryptor has not been set into Hibernate wrapper");
        }
        return encryptor.encrypt(message);
    }

    
    public String decrypt(String encryptedMessage) {
        if (this.encryptor == null) {
            throw new EncryptionInitializationException(
                    "Encryptor has not been set into Hibernate wrapper");
        }
        return encryptor.decrypt(encryptedMessage);
    }
    
    
}
