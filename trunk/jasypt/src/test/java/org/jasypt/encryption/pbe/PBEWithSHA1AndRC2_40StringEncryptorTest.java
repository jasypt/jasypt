package org.jasypt.encryption.pbe;


public class PBEWithSHA1AndRC2_40StringEncryptorTest 
        extends AbstractPBEStringEncryptorTest {

    protected PBEStringEncryptor createPBEStringEncryptor() {
        return new PBEWithSHA1AndRC2_40StringEncryptor();
    }

}
