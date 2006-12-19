package org.jasypt.pbe;

public interface PBEStringEncryptor {
    
    public String encrypt(String message);
    
    public String decrypt(String encryptedMessage);
    
}
