package org.jasypt.encryption.pbe;

import org.jasypt.encryption.ByteEncryptor;

public interface PBEByteEncryptor extends ByteEncryptor {

    public void setPassword(String password);
    
}
