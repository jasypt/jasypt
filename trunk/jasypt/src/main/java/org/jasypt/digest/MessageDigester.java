package org.jasypt.digest;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.Validate;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;


public class MessageDigester implements Digester {

    public static final boolean DEFAULT_BASE64_ENCODED = true;
    public static final String DEFAULT_ALGORITHM = "MD5";

    private String algorithm = DEFAULT_ALGORITHM;
    private boolean base64Encoded = DEFAULT_BASE64_ENCODED;

    private boolean initialized = false;
    
    private MessageDigest md = null;
    private Base64 base64 = new Base64();


    
    public synchronized void setBase64Encoded(boolean base64Encoded) {
        if (this.base64Encoded != base64Encoded) {
            this.base64Encoded = base64Encoded;
            initialized = false;
        }
    }

    public synchronized void setAlgorithm(String algorithm) {
        Validate.notEmpty(algorithm);
        if (!this.algorithm.equals(algorithm)) {
            this.algorithm = algorithm;
            initialized = false;
        }
    }

    public boolean isBase64Encoded() {
        return base64Encoded;
    }
    
    public String getAlgorithm() {
        return algorithm;
    }

    
    private synchronized void initialize() {
        try {
            md = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new EncryptionOperationNotPossibleException(e);
        }
        initialized = true;
    }
    
    
    public synchronized String digest(String message) {
        
        Validate.notNull(message);
        
        if (!initialized) {
            initialize();
        }
        
        md.update(message.getBytes());
        byte[] encryptedBytes = null;
        try {
            encryptedBytes = md.digest();
        } catch (Exception e) {
            throw new EncryptionOperationNotPossibleException();
        }
        if (base64Encoded) {
            return new String(base64.encode(encryptedBytes));
        } else {
            return new String(encryptedBytes);
        }
        
    }

    
}
