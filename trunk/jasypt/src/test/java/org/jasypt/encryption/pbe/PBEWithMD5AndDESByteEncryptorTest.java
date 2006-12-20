package org.jasypt.encryption.pbe;


public class PBEWithMD5AndDESByteEncryptorTest 
        extends AbstractPBEByteEncryptorTest {

    protected PBEByteEncryptor createPBEByteEncryptor() {
        return new PBEWithMD5AndDESByteEncryptor();
    }


}
