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

import java.util.HashMap;

import org.jasypt.encryption.pbe.PBEStringEncryptor;

public class HibernatePBEEncryptorRegistry {

    
    private static HibernatePBEEncryptorRegistry instance = 
        new HibernatePBEEncryptorRegistry();
    
    
    private HashMap configs = new HashMap();
    
    
    public static HibernatePBEEncryptorRegistry getInstance() {
        return instance;
    }
    
    private HibernatePBEEncryptorRegistry() { }
 

    public synchronized void registerPBEEncryptor(
            String name, PBEStringEncryptor encryptor) {
        HibernatePBEEncryptor hibernateEncryptor = 
            new HibernatePBEEncryptor(name, encryptor);
        this.configs.put(name, hibernateEncryptor);
    }

    synchronized void registerHibernatePBEEncryptor(
            HibernatePBEEncryptor hibernateEncryptor) {
        this.configs.put(hibernateEncryptor.getName(), hibernateEncryptor);
    }
    
    synchronized void unregisterHibernatePBEEncryptor(String name) {
        this.configs.remove(name);
    }
    
    public synchronized HibernatePBEEncryptor getHibernatePBEEncryptor(
            String name) {
        return (HibernatePBEEncryptor) configs.get(name);
    }
    
}
