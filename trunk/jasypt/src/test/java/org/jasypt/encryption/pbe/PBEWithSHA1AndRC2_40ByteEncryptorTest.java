package org.jasypt.encryption.pbe;


public class PBEWithSHA1AndRC2_40ByteEncryptorTest 
        extends AbstractPBEByteEncryptorTest {

    protected PBEByteEncryptor createPBEByteEncryptor() {
        return new PBEWithSHA1AndRC2_40ByteEncryptor();
    }

}
