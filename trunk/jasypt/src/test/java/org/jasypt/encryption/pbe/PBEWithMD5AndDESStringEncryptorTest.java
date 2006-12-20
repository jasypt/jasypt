package org.jasypt.encryption.pbe;


public class PBEWithMD5AndDESStringEncryptorTest 
        extends AbstractPBEStringEncryptorTest {

    protected PBEStringEncryptor createPBEStringEncryptor() {
        return new PBEWithMD5AndDESStringEncryptor();
    }

    
}
