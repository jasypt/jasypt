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
package org.jasypt.digest;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.Validate;
import org.jasypt.digest.config.DigesterConfig;
import org.jasypt.exceptions.AlreadyInitializedException;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.jasypt.salt.SaltGeneration;


// TODO: Add comments
// TODO: Add Javadoc
public final class StandardByteDigester implements ByteDigester {

    public static final String DEFAULT_ALGORITHM = "MD5";
    public static final int DEFAULT_SALT_SIZE_BYTES = 8;
    public static final int DEFAULT_ITERATIONS = 1000;

    private String algorithm = DEFAULT_ALGORITHM;
    private int saltSizeBytes = DEFAULT_SALT_SIZE_BYTES;
    private int iterations = DEFAULT_ITERATIONS;
    
    private DigesterConfig config = null;

    private boolean algorithmSet = false;
    private boolean saltSizeBytesSet = false;
    private boolean iterationsSet = false;
    
    private boolean initialized = false;
    
    private boolean useSalt = true;
    
    private MessageDigest md = null;

    

    public synchronized void setConfig(DigesterConfig config) {
        Validate.notNull(config, "Config cannot be set null");
        if (isInitialized()) {
            throw new AlreadyInitializedException();
        }
        this.config = config;
    }
    
    public synchronized void setAlgorithm(String algorithm) {
        Validate.notEmpty(algorithm, "Algorithm cannot be empty");
        if (isInitialized()) {
            throw new AlreadyInitializedException();
        }
        this.algorithm = algorithm;
        this.algorithmSet = true;
    }
    
    public synchronized void setSaltSizeBytes(int saltSizeBytes) {
        Validate.isTrue(saltSizeBytes >= 0, 
                "Salt size in bytes must be non-negative");
        if (isInitialized()) {
            throw new AlreadyInitializedException();
        }
        this.saltSizeBytes = saltSizeBytes;
        this.useSalt = (saltSizeBytes > 0);
        this.saltSizeBytesSet = true;
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
    

    private synchronized boolean isInitialized() {
        return this.initialized;
    }
    

    private synchronized void initialize() {
        if (!this.initialized) {
            
            if (this.config != null) {
                
                String configAlgorithm = config.getAlgorithm();
                Integer configSaltSizeBytes = config.getSaltSizeBytes();
                Integer configIterations = config.getIterations();
                
                this.algorithm = 
                    ((this.algorithmSet) || (configAlgorithm == null))?
                            this.algorithm : configAlgorithm;
                this.saltSizeBytes = 
                    ((this.saltSizeBytesSet) || (configSaltSizeBytes == null))?
                            this.saltSizeBytes : configSaltSizeBytes.intValue();
                this.iterations = 
                    ((this.iterationsSet) || (configIterations == null))?
                            this.iterations : configIterations.intValue();
                
            }
            
            try {
                this.md = MessageDigest.getInstance(this.algorithm);
            } catch (NoSuchAlgorithmException e) {
                throw new EncryptionInitializationException(e);
            }
            this.initialized = true;
        }
    }
    
    
    
    public byte[] digest(byte[] message) {
        
        if (message == null) {
            return null;
        }
        
        if (!isInitialized()) {
            initialize();
        }
        
        byte[] salt = null;
        if (this.useSalt) {
            salt = SaltGeneration.generateSalt(this.saltSizeBytes);
        }
        
        return digest(message, salt);
        
    }

    
    
    private byte[] digest(byte[] message, byte[] salt) {
        
        try {
            
            byte[] encryptedMessage = new byte[0];

            if (salt != null) {
                encryptedMessage = ArrayUtils.addAll(encryptedMessage, salt);
            }

            byte[] digest = null;
            
            synchronized (this.md) {
                
                this.md.reset();
                
                if (salt != null) {
                    this.md.update(salt);
                }
                this.md.update(message);
                
                digest = this.md.digest();
                for (int i = 0; i < (this.iterations - 1); i++) {
                    this.md.reset();
                    digest = this.md.digest(digest);
                }
                
            }
            
            encryptedMessage = ArrayUtils.addAll(encryptedMessage, digest);
            
            return encryptedMessage;
        
        } catch (Exception e) {
            throw new EncryptionOperationNotPossibleException();
        }
        
    }
    
    
    public boolean matches(byte[] message, byte[] digest) {

        if (message == null) {
            return (digest == null);
        } else if (digest == null) {
            return false;
        }
        
        if (!isInitialized()) {
            initialize();
        }
        
        try {

            byte[] salt = null;
            if (this.useSalt) {
                salt = ArrayUtils.subarray(digest, 0, this.saltSizeBytes);
            }
            
            byte[] encryptedMessage = digest(message, salt);
            
            return (Arrays.equals(encryptedMessage, digest));
        
        } catch (Exception e) {
            throw new EncryptionOperationNotPossibleException();
        }
        
    }

    
    
    
    
}
