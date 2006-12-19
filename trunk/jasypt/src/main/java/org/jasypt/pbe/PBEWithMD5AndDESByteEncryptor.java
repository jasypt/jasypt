package org.jasypt.pbe;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.Validate;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.jasypt.salt.SaltGeneration;

// TODO: Extract Abstract class and create sibling clases for other algorithms
// TODO: Create StringEncryptor classes
// TODO: Add messages to Validate actions
// TODO: Add comments
// TODO: Add javadoc
public final class PBEWithMD5AndDESByteEncryptor implements PBEByteEncryptor {
    
    public static final int DEFAULT_ITERATIONS = 1000;

    private static final String ALGORITHM = "PBEWithMD5AndDES";
    private static final int SALT_SIZE_BYTES = 8;
    
    private String password = null;
    private int iterations = DEFAULT_ITERATIONS;
    
    private boolean initialized = false;
    
    private SecretKey key = null;
    private Cipher encryptCipher = null;
    private Cipher decryptCipher = null;
    

    

    public synchronized void setPassword(String password) {
        Validate.notEmpty(password);
        if ((this.password == null) || (!this.password.equals(password))) {
            this.password = password;
            initialized = false;
        }
    }
    
    public synchronized void setIterations(int iterations) {
        Validate.isTrue(iterations > 0);
        this.iterations = iterations;
    }
    

    private synchronized void initialize() {
        
        if (!initialized) {
            
            try {
                
                if (password == null) {
                    throw new EncryptionInitializationException(
                            "Password not set for Password Based Encryptor");
                }
                
                PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
                SecretKeyFactory factory =
                    SecretKeyFactory.getInstance(ALGORITHM);
                
                key = factory.generateSecret(pbeKeySpec);
                
                encryptCipher = Cipher.getInstance(ALGORITHM);
                decryptCipher = Cipher.getInstance(ALGORITHM);
                
            } catch (EncryptionInitializationException e) {
                throw e;
            } catch (Throwable t) {
                throw new EncryptionInitializationException(t);
            }
            initialized = true;
        }
        
    }


    public synchronized byte[] encrypt(byte[] message) 
            throws EncryptionOperationNotPossibleException {
        
        Validate.notNull(message);
        
        if (!initialized) {
            initialize();
        }
        
        try {
            
            byte[] salt = SaltGeneration.generateSalt(SALT_SIZE_BYTES);
            
            PBEParameterSpec parameterSpec = 
                new PBEParameterSpec(salt, iterations);

            byte[] encyptedMessage = null;
            synchronized (encryptCipher) {
                encryptCipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
                encyptedMessage = encryptCipher.doFinal(message);
            }
            
            return ArrayUtils.addAll(salt, encyptedMessage);
            
        } catch (Exception e) {
            throw new EncryptionOperationNotPossibleException();
        }
        
    }

    
    
    public synchronized byte[] decrypt(byte[] encryptedMessage) 
            throws EncryptionOperationNotPossibleException {
        
        Validate.notNull(encryptedMessage);
        
        if (!initialized) {
            initialize();
        }
    
        try {
            
            byte[] salt = 
                ArrayUtils.subarray(encryptedMessage, 0, SALT_SIZE_BYTES);

            
            PBEParameterSpec parameterSpec = 
                new PBEParameterSpec(salt, iterations);

            byte[] decryptedMessage = null;
            synchronized (decryptCipher) {
                decryptCipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
                decryptedMessage = 
                    decryptCipher.doFinal(
                            ArrayUtils.subarray(
                                    encryptedMessage, 
                                    SALT_SIZE_BYTES, 
                                    encryptedMessage.length));
            }
            
            return decryptedMessage;
            
        } catch (Exception e) {
            throw new EncryptionOperationNotPossibleException();
        }
        
    }    

    
}

