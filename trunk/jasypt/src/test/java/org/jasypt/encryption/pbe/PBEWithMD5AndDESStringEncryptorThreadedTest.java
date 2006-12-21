package org.jasypt.encryption.pbe;



public class PBEWithMD5AndDESStringEncryptorThreadedTest 
        extends AbstractPBEStringEncryptorThreadedTest {

    protected PBEStringEncryptor createEncryptor() {
        return new PBEWithMD5AndDESStringEncryptor();
    }

    
}
