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

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.Validate;
import org.jasypt.encryption.pbe.algorithms.PBEAlgorithms;
import org.jasypt.encryption.pbe.config.PBEConfig;
import org.jasypt.exceptions.AlreadyInitializedException;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.jasypt.salt.SaltGeneration;

// TODO: Add comments
// TODO: Add javadoc
public final class StandardPBEByteEncryptor implements PBEByteEncryptor {
    
    public static final int DEFAULT_ITERATIONS = 1000;

    private String algorithm = null;
    private String password = null;
    private int keyObtentionIterations = DEFAULT_ITERATIONS;

    private int saltSizeBytes = 0;
    
    private PBEConfig config = null;

    private boolean algorithmSet = false;
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

    
    public synchronized void setAlgorithm(String algorithm) {
        Validate.notEmpty(algorithm, "Algorithm cannot be set empty");
        PBEAlgorithms.validateAlgorithm(algorithm);
        if (isInitialized()) {
            throw new AlreadyInitializedException();
        }
        this.algorithm = algorithm;
        this.algorithmSet = true;
    }
    
    
    public synchronized void setPassword(String password) {
        Validate.notEmpty(password, "Password cannot be set empty");
        if (isInitialized()) {
            throw new AlreadyInitializedException();
        }
        this.password = password;
        this.passwordSet = true;
    }
    
    public synchronized void setKeyObtentionIterations(
            int keyObtentionIterations) {
        Validate.isTrue(keyObtentionIterations > 0, 
                "Number of iterations for key obtention must be " +
                "greater than zero");
        if (isInitialized()) {
            throw new AlreadyInitializedException();
        }
        this.keyObtentionIterations = keyObtentionIterations;
        this.iterationsSet = true;
    }
    
    
    public synchronized boolean isInitialized() {
        return this.initialized;
    }

    public synchronized void initialize() {
        
        if (!this.initialized) {
            
            if (this.config != null) {
                
                String configAlgorithm = config.getAlgorithm();
                if (configAlgorithm != null) {
                    Validate.notEmpty(password, 
                            "Algorithm cannot be set empty");
                    PBEAlgorithms.validateAlgorithm(algorithm);
                }
                
                
                String configPassword = config.getPassword();
                if (configPassword != null) {
                    Validate.notEmpty(configPassword, 
                            "Password cannot be set empty");
                }
                
                Integer configKeyObtentionIterations = 
                    config.getKeyObtentionIterations();
                if (configKeyObtentionIterations != null) {
                    Validate.isTrue(configKeyObtentionIterations.intValue() > 0, 
                            "Number of iterations for key obtention must be " +
                            "greater than zero");
                }
                
                this.algorithm = 
                    ((this.algorithmSet) || (configAlgorithm == null))?
                            this.algorithm : configAlgorithm;
                this.password = 
                    ((this.passwordSet) || (configPassword == null))?
                            this.password : configPassword;
                this.keyObtentionIterations = 
                    ((this.iterationsSet) || 
                     (configKeyObtentionIterations == null))?
                            this.keyObtentionIterations : 
                            configKeyObtentionIterations.intValue();
                
            }
            
            PBEAlgorithms.Parameters parameters =
                PBEAlgorithms.getParameters(this.algorithm);
            
            this.saltSizeBytes = parameters.getSaltSizeBytes();
            
            try {
                
                if (this.password == null) {
                    throw new EncryptionInitializationException(
                            "Password not set for Password Based Encryptor");
                }
                
                PBEKeySpec pbeKeySpec = 
                    new PBEKeySpec(this.password.toCharArray());
                SecretKeyFactory factory =
                    SecretKeyFactory.getInstance(this.algorithm);
                
                this.key = factory.generateSecret(pbeKeySpec);
                
                this.encryptCipher = Cipher.getInstance(this.algorithm);
                this.decryptCipher = Cipher.getInstance(this.algorithm);
                
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
            
            byte[] salt = SaltGeneration.generateSalt(this.saltSizeBytes);
            
            PBEParameterSpec parameterSpec = 
                new PBEParameterSpec(salt, this.keyObtentionIterations);

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
                ArrayUtils.subarray(encryptedMessage, 0, this.saltSizeBytes);

            
            PBEParameterSpec parameterSpec = 
                new PBEParameterSpec(salt, this.keyObtentionIterations);

            byte[] decryptedMessage = null;
            
            byte[] encryptedMessageKernel = 
                ArrayUtils.subarray(encryptedMessage, this.saltSizeBytes, 
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

