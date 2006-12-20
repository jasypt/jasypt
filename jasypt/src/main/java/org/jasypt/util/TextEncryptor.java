package org.jasypt.util;

public interface TextEncryptor {

    public void setPassword(String password);

    public String encrypt(String message);

    public String decrypt(String encryptedMessage);

}