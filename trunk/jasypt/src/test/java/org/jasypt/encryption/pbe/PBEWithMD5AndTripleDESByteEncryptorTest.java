package org.jasypt.encryption.pbe;


public class PBEWithMD5AndTripleDESByteEncryptorTest 
        extends AbstractPBEByteEncryptorTest {

    protected PBEByteEncryptor createPBEByteEncryptor() {
        return new PBEWithMD5AndTripleDESByteEncryptor();
    }


}
