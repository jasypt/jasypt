package org.jasypt.pbe;

public interface PBEByteEncryptor {

    public byte[] encrypt(byte[] message);
    
    public byte[] decrypt(byte[] encryptedMessage);
    
}
