package org.jasypt.util;

import org.jasypt.encryption.pbe.PBEWithMD5AndDESStringEncryptor;

public final class NormalTextEncryptor implements TextEncryptor {

    
    private PBEWithMD5AndDESStringEncryptor encryptor = null;
    
    
    public NormalTextEncryptor() {
        this.encryptor = new PBEWithMD5AndDESStringEncryptor();
    }
    
    public void setPassword(String password) {
        encryptor.setPassword(password);
    }

    
    public String encrypt(String message) {
        return encryptor.encrypt(message);
    }
    
    public String decrypt(String encryptedMessage) {
        return encryptor.decrypt(encryptedMessage);
    }
    
}
