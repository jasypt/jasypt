package org.jasypt.encryption;

public interface ByteEncryptor {

    public byte[] encrypt(byte[] message);
    
    public byte[] decrypt(byte[] encryptedMessage);
    
}
