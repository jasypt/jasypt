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
package org.jasypt.encryption.pbe;

import org.apache.commons.codec.binary.Base64;
import org.jasypt.encryption.pbe.config.PBEConfig;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;


public final class StandardPBEStringEncryptor implements PBEStringEncryptor {

    private static final String MESSAGE_CHARSET = "UTF-8";
    private static final String ENCRYPTED_MESSAGE_CHARSET = "US-ASCII";

    private StandardPBEByteEncryptor byteEncryptor = null;
    private Base64 base64 = null;

    
    public StandardPBEStringEncryptor() {
        this.byteEncryptor = new StandardPBEByteEncryptor();
        this.base64 = new Base64();
    }
    
    public void setConfig(PBEConfig config) {
        byteEncryptor.setConfig(config);
    }
    
    public void setAlgorithm(String algorithm) {
        byteEncryptor.setAlgorithm(algorithm);
    }
    
    public void setPassword(String password) {
        byteEncryptor.setPassword(password);
    }
    

    public void setKeyObtentionIterations(int keyObtentionIterations) {
        byteEncryptor.setKeyObtentionIterations(keyObtentionIterations);
    }
    
    public boolean isInitialized() {
        return byteEncryptor.isInitialized();
    }
    
    public void initialize() {
        byteEncryptor.initialize();
    }
    
    
    
    public String encrypt(String message) {
        
        if (message == null) {
            return null;
        }
        
        try {

            byte[] messageBytes = message.getBytes(MESSAGE_CHARSET);
            
            byte[] encryptedMessage = byteEncryptor.encrypt(messageBytes);
            
            synchronized (base64) {
                encryptedMessage = base64.encode(encryptedMessage);
            }
            
            return new String(encryptedMessage, 
                    ENCRYPTED_MESSAGE_CHARSET);
        
        } catch (EncryptionInitializationException e) {
            throw e;
        } catch (EncryptionOperationNotPossibleException e) {
            throw e;
        } catch (Exception e) {
            throw new EncryptionOperationNotPossibleException();
        }
        
    }

    
    
    public String decrypt(String encryptedMessage) {
        
        if (encryptedMessage == null) {
            return null;
        }
        
        try {
            
            byte[] encryptedMessageBytes = 
                encryptedMessage.getBytes(ENCRYPTED_MESSAGE_CHARSET);
            
            synchronized (base64) {
                encryptedMessageBytes = base64.decode(encryptedMessageBytes);
            }
            
            byte[] message = byteEncryptor.decrypt(encryptedMessageBytes);
            
            return new String(message, MESSAGE_CHARSET);
        
        } catch (EncryptionInitializationException e) {
            throw e;
        } catch (EncryptionOperationNotPossibleException e) {
            throw e;
        } catch (Exception e) {
            throw new EncryptionOperationNotPossibleException();
        }

    }

    
}
