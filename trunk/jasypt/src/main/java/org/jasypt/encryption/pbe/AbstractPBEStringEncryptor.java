package org.jasypt.encryption.pbe;

import org.apache.commons.codec.binary.Base64;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;


public abstract class AbstractPBEStringEncryptor implements PBEStringEncryptor {

    private static final String MESSAGE_CHARSET = "UTF-8";
    private static final String ENCRYPTED_MESSAGE_CHARSET = "US-ASCII";

    private AbstractPBEByteEncryptor byteEncryptor = null;
    private Base64 base64 = null;

    
    public AbstractPBEStringEncryptor() {
        this.byteEncryptor = createByteEncryptorInstance();
        this.base64 = new Base64();
    }

    
    protected abstract AbstractPBEByteEncryptor createByteEncryptorInstance();
    
    
    public synchronized void setPassword(String password) {
        byteEncryptor.setPassword(password);
    }
    

    public synchronized void setIterations(int iterations) {
        byteEncryptor.setIterations(iterations);
    }
    
    
    
    public synchronized String encrypt(String message) {
        
        if (message == null) {
            return null;
        }
        
        try {

            byte[] messageBytes = message.getBytes(MESSAGE_CHARSET);
            byte[] encryptedMessage = 
                base64.encode(byteEncryptor.encrypt(messageBytes));
            
            return new String(encryptedMessage, 
                    ENCRYPTED_MESSAGE_CHARSET);
        
        } catch (EncryptionInitializationException e) {
            throw e;
        } catch (Exception e) {
            throw new EncryptionOperationNotPossibleException();
        }
        
    }

    
    
    public synchronized String decrypt(String encryptedMessage) {
        
        if (encryptedMessage == null) {
            return null;
        }
        
        try {
            
            byte[] encryptedMessageBytes =
                base64.decode(
                    encryptedMessage.getBytes(
                            ENCRYPTED_MESSAGE_CHARSET));
            
            byte[] message = byteEncryptor.decrypt(encryptedMessageBytes);
            
            return new String(message, MESSAGE_CHARSET);
        
        } catch (EncryptionInitializationException e) {
            throw e;
        } catch (Exception e) {
            throw new EncryptionOperationNotPossibleException();
        }

    }

    
}
