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
package org.jasypt.encryption.pbe;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.Validate;
import org.jasypt.encryption.pbe.config.PBEConfig;
import org.jasypt.exceptions.AlreadyInitializedException;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.jasypt.salt.SaltGeneration;

// TODO: Add comments
// TODO: Add javadoc
public abstract class AbstractPBEByteEncryptor implements PBEByteEncryptor {
    
    public static final int DEFAULT_ITERATIONS = 1000;

    private String password = null;
    private int iterations = DEFAULT_ITERATIONS;
    private PBEConfig config = null;
    
    private boolean passwordSet = false;
    private boolean iterationsSet = false;
    
    private boolean initialized = false;
    
    private SecretKey key = null;
    private Cipher encryptCipher = null;
    private Cipher decryptCipher = null;
    

    

    public synchronized void setConfig(PBEConfig config) {
        Validate.notNull(config, "Config cannot be set null");
        if (isInitialized()) {
            throw new AlreadyInitializedException();
        }
        this.config = config;
    }

    public synchronized void setPassword(String password) {
        Validate.notEmpty(password, "Password cannot be set empty");
        if (isInitialized()) {
            throw new AlreadyInitializedException();
        }
        this.password = password;
        this.passwordSet = true;
    }
    
    public synchronized void setIterations(int iterations) {
        Validate.isTrue(iterations > 0, 
                "Number of iterations must be greater than zero");
        if (isInitialized()) {
            throw new AlreadyInitializedException();
        }
        this.iterations = iterations;
        this.iterationsSet = true;
    }
    
    
    protected abstract String getAlgorithm();
    
    protected abstract int getSaltSizeBytes(); 
    
    
    private synchronized boolean isInitialized() {
        return this.initialized;
    }

    private synchronized void initialize() {
        
        if (!this.initialized) {
            
            if (this.config != null) {
                
                String configPassword = config.getPassword();
                Integer configIterations = config.getIterations();
                
                this.password = 
                    ((this.passwordSet) || (configPassword == null))?
                            this.password : configPassword;
                this.iterations = 
                    ((this.iterationsSet) || (configIterations == null))?
                            this.iterations : configIterations.intValue();
            }
            
            try {
                
                if (this.password == null) {
                    throw new EncryptionInitializationException(
                            "Password not set for Password Based Encryptor");
                }
                
                PBEKeySpec pbeKeySpec = 
                    new PBEKeySpec(this.password.toCharArray());
                SecretKeyFactory factory =
                    SecretKeyFactory.getInstance(getAlgorithm());
                
                this.key = factory.generateSecret(pbeKeySpec);
                
                this.encryptCipher = Cipher.getInstance(getAlgorithm());
                this.decryptCipher = Cipher.getInstance(getAlgorithm());
                
            } catch (EncryptionInitializationException e) {
                throw e;
            } catch (Throwable t) {
                throw new EncryptionInitializationException(t);
            }
            this.initialized = true;
        }
        
    }


    public byte[] encrypt(byte[] message) 
            throws EncryptionOperationNotPossibleException {
        
        if (message == null) {
            return null;
        }
        
        if (!isInitialized()) {
            initialize();
        }
        
        try {
            
            byte[] salt = SaltGeneration.generateSalt(getSaltSizeBytes());
            
            PBEParameterSpec parameterSpec = 
                new PBEParameterSpec(salt, this.iterations);

            byte[] encyptedMessage = null;
            synchronized (this.encryptCipher) {
                this.encryptCipher.init(
                        Cipher.ENCRYPT_MODE, this.key, parameterSpec);
                encyptedMessage = this.encryptCipher.doFinal(message);
            }
            
            return ArrayUtils.addAll(salt, encyptedMessage);
            
        } catch (Exception e) {
            throw new EncryptionOperationNotPossibleException();
        }
        
    }

    
    
    public byte[] decrypt(byte[] encryptedMessage) 
            throws EncryptionOperationNotPossibleException {
        
        if (encryptedMessage == null) {
            return null;
        }
        
        if (!isInitialized()) {
            initialize();
        }
    
        try {
            
            byte[] salt = 
                ArrayUtils.subarray(encryptedMessage, 0, getSaltSizeBytes());

            
            PBEParameterSpec parameterSpec = 
                new PBEParameterSpec(salt, this.iterations);

            byte[] decryptedMessage = null;
            
            byte[] encryptedMessageKernel = 
                ArrayUtils.subarray(encryptedMessage,getSaltSizeBytes(), 
                        encryptedMessage.length);
                 
            synchronized (this.decryptCipher) {
                this.decryptCipher.init(
                        Cipher.DECRYPT_MODE, this.key, parameterSpec);
                decryptedMessage = 
                    this.decryptCipher.doFinal(encryptedMessageKernel);
            }
            
            return decryptedMessage;
            
        } catch (Exception e) {
            throw new EncryptionOperationNotPossibleException();
        }
        
    }    

    
}

