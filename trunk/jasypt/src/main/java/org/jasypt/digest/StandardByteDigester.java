package org.jasypt.digest;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.Validate;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.jasypt.salt.SaltGeneration;


// TODO: Add configurator
// TODO: Add comments
// TODO: Add Javadoc
public final class StandardByteDigester implements ByteDigester {

    public static final String DEFAULT_ALGORITHM = "MD5";
    public static final int DEFAULT_SALT_SIZE_BYTES = 8;
    public static final int DEFAULT_ITERATIONS = 1000;

    private String algorithm = DEFAULT_ALGORITHM;
    private int saltSizeBytes = DEFAULT_SALT_SIZE_BYTES;
    private int iterations = DEFAULT_ITERATIONS;
    
    private boolean initialized = false;
    private boolean useSalt = true;
    
    private MessageDigest md = null;

    

    public synchronized void setAlgorithm(String algorithm) {
        Validate.notEmpty(algorithm, "Algorithm cannot be empty");
        if (!this.algorithm.equals(algorithm)) {
            this.algorithm = algorithm;
            initialized = false;
        }
    }
    
    public synchronized void setSaltSizeBytes(int saltSizeBytes) {
        Validate.isTrue(saltSizeBytes >= 0, 
                "Salt size in bytes must be non-negative");
        this.saltSizeBytes = saltSizeBytes;
        this.useSalt = (saltSizeBytes > 0);
    }

    public synchronized void setIterations(int iterations) {
        Validate.isTrue(iterations > 0, 
                "Number of iterations must be greater than zero");
        this.iterations = iterations;
    }
    

    public String getAlgorithm() {
        return algorithm;
    }
    
    public int getIterations() {
        return iterations;
    }

    public int getSaltSizeBytes() {
        return saltSizeBytes;
    }
    
    private synchronized boolean isInitialized() {
        return initialized;
    }

    private synchronized void initialize() {
        if (!initialized) {
            try {
                md = MessageDigest.getInstance(algorithm);
            } catch (NoSuchAlgorithmException e) {
                throw new EncryptionInitializationException(e);
            }
            initialized = true;
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
        if (useSalt) {
            salt = SaltGeneration.generateSalt(saltSizeBytes);
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
            
            synchronized (md) {
                
                md.reset();
                
                if (salt != null) {
                    md.update(salt);
                }
                md.update(message);
                
                digest = md.digest();
                for (int i = 0; i < (iterations - 1); i++) {
                    md.reset();
                    digest = md.digest(digest);
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
            if (useSalt) {
                salt = ArrayUtils.subarray(digest, 0, saltSizeBytes);
            }
            
            byte[] encryptedMessage = digest(message, salt);
            
            return (Arrays.equals(encryptedMessage, digest));
        
        } catch (Exception e) {
            throw new EncryptionOperationNotPossibleException();
        }
        
    }

    
    
    
    
}
