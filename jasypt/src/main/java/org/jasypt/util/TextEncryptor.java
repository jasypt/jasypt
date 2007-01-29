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


/**
 * Common interface for <i>easy</i> encryptors.
 *
 * 
 * @since 1.0
 * 
 * @author Daniel Fern&aacute;ndez Garrido
 * 
 * 
 */
public interface TextEncryptor {

    
    /**
     * Sets a password.
     * 
     * @param password the password to be set.
     */
    public void setPassword(String password);

    
    /**
     * Encrypts a message.
     * 
     * @param message the message to be encrypted.
     */
    public String encrypt(String message);

    
    /**
     * Decrypts a message.
     * 
     * @param encryptedMessage the message to be decrypted.
     */
    public String decrypt(String encryptedMessage);

}