package org.jasypt.digest;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.Validate;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;


public final class StandardStringDigester implements StringDigester {

    private static final String MESSAGE_DECODING_CHARSET = "UTF-8";
    private static final String DIGEST_ENCODING_CHARSET = "US-ASCII";

    private StandardByteDigester byteDigester = null;
    private Base64 base64 = null;

    
    public StandardStringDigester() {
        this.byteDigester = new StandardByteDigester();
        this.base64 = new Base64();
    }
    
    
    public synchronized void setAlgorithm(String algorithm) {
        byteDigester.setAlgorithm(algorithm);
    }
    
    public synchronized void setSaltSizeBytes(int saltSizeBytes) {
        byteDigester.setSaltSizeBytes(saltSizeBytes);
    }

    public synchronized void setIterations(int iterations) {
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
    
    
    
    public synchronized String digest(String message) {
        
        Validate.notNull(message);
        
        try {

            byte[] messageBytes = message.getBytes(MESSAGE_DECODING_CHARSET);
            byte[] digest = base64.encode(byteDigester.digest(messageBytes));
            
            return new String(digest, DIGEST_ENCODING_CHARSET);
        
        } catch (Exception e) {
            throw new EncryptionOperationNotPossibleException();
        }
        
    }

    
    
    public synchronized boolean matches(String message, String digest) {
        
        Validate.notNull(message);
        Validate.notNull(digest);
        
        try {
            
            byte[] messageBytes = message.getBytes(MESSAGE_DECODING_CHARSET);
            byte[] digestBytes = digest.getBytes(DIGEST_ENCODING_CHARSET);
            
            return byteDigester.matches(
                    messageBytes, 
                    base64.decode(digestBytes)); 
        
        } catch (Exception e) {
            throw new EncryptionOperationNotPossibleException();
        }

    }
    
    
}