package org.jasypt.pbe;

public interface BytePBEncryptor {

    public byte[] encrypt(byte[] message);
    
    public byte[] decrypt(byte[] encryptedMessage);
    
}
