package org.jasypt.digest;

import org.apache.commons.codec.binary.Base64;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;


public final class StandardStringDigester implements StringDigester {

    private static final String MESSAGE_CHARSET = "UTF-8";
    private static final String DIGEST_CHARSET = "US-ASCII";

    private StandardByteDigester byteDigester = null;
    private Base64 base64 = null;

    
    public StandardStringDigester() {
        this.byteDigester = new StandardByteDigester();
        this.base64 = new Base64();
    }
    
    
    public void setAlgorithm(String algorithm) {
        byteDigester.setAlgorithm(algorithm);
    }
    
    public void setSaltSizeBytes(int saltSizeBytes) {
        byteDigester.setSaltSizeBytes(saltSizeBytes);
    }

    public void setIterations(int iterations) {
        byteDigester.setIterations(iterations);
    }
    

    public String getAlgorithm() {
        return byteDigester.getAlgorithm();
    }
    
    public int getIterations() {
        return byteDigester.getIterations();
    }

    public int getSaltSizeBytes() {
        return byteDigester.getSaltSizeBytes();
    }
    
    
    
    public String digest(String message) {
        
        if (message == null) {
            return null;
        }
        
        try {

            byte[] messageBytes = message.getBytes(MESSAGE_CHARSET);
            
            byte[] digest = byteDigester.digest(messageBytes);
            
            synchronized (base64) {
                digest = base64.encode(digest);
            }
            
            return new String(digest, DIGEST_CHARSET);
        
        } catch (Exception e) {
            throw new EncryptionOperationNotPossibleException();
        }
        
    }

    
    
    public boolean matches(String message, String digest) {

        if (message == null) {
            return (digest == null);
        } else if (digest == null) {
            return false;
        }
        
        try {
            
            byte[] messageBytes = message.getBytes(MESSAGE_CHARSET);
            byte[] digestBytes = digest.getBytes(DIGEST_CHARSET);
            
            synchronized (base64) {
                digestBytes = base64.decode(digestBytes);
            }
            
            return byteDigester.matches(messageBytes, digestBytes); 
        
        } catch (Exception e) {
            throw new EncryptionOperationNotPossibleException();
        }

    }
    
    
}
