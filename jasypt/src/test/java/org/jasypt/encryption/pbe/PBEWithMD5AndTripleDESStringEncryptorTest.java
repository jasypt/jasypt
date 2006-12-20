package org.jasypt.encryption.pbe;


public class PBEWithMD5AndTripleDESStringEncryptorTest 
        extends AbstractPBEStringEncryptorTest {

    protected PBEStringEncryptor createPBEStringEncryptor() {
        return new PBEWithMD5AndTripleDESStringEncryptor();
    }

}
