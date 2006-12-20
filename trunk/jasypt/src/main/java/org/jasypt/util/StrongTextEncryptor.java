package org.jasypt.util;

import org.jasypt.encryption.pbe.PBEWithMD5AndTripleDESStringEncryptor;

public final class StrongTextEncryptor implements TextEncryptor {

    
    private PBEWithMD5AndTripleDESStringEncryptor encryptor = null;
    
    
    public StrongTextEncryptor() {
        this.encryptor = new PBEWithMD5AndTripleDESStringEncryptor();
    }
    
    public synchronized void setPassword(String password) {
        encryptor.setPassword(password);
    }

    
    public synchronized String encrypt(String message) {
        return encryptor.encrypt(message);
    }
    
    public synchronized String decrypt(String encryptedMessage) {
        return encryptor.decrypt(encryptedMessage);
    }
    
}
