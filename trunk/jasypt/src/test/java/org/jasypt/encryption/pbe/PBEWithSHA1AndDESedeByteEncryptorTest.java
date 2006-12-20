package org.jasypt.encryption.pbe;


public class PBEWithSHA1AndDESedeByteEncryptorTest 
        extends AbstractPBEByteEncryptorTest {

    protected PBEByteEncryptor createPBEByteEncryptor() {
        return new PBEWithSHA1AndDESedeByteEncryptor();
    }

}
