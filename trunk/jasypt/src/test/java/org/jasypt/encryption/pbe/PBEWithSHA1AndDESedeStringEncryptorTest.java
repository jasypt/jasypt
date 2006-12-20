package org.jasypt.encryption.pbe;


public class PBEWithSHA1AndDESedeStringEncryptorTest 
        extends AbstractPBEStringEncryptorTest {

    protected PBEStringEncryptor createPBEStringEncryptor() {
        return new PBEWithSHA1AndDESedeStringEncryptor();
    }

}
