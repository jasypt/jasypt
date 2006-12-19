package org.jasypt.pbe;

public interface StringPBEncryptor {
    
    public String encrypt(String message);
    
    public String decrypt(String encryptedMessage);
    
}
