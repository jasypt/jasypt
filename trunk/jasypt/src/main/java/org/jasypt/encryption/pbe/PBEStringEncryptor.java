package org.jasypt.encryption.pbe;

import org.jasypt.encryption.StringEncryptor;

public interface PBEStringEncryptor extends StringEncryptor {

    public void setPassword(String password);
    
}
