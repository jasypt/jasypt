package org.jasypt.encryption;

public interface StringEncryptor {
    
    public String encrypt(String message);
    
    public String decrypt(String encryptedMessage);
    
}
