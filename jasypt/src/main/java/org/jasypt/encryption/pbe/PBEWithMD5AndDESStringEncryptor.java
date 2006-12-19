package org.jasypt.encryption.pbe;



public final class PBEWithMD5AndDESStringEncryptor 
        extends AbstractPBEStringEncryptor {

    protected AbstractPBEByteEncryptor createByteEncryptorInstance() {
        return new PBEWithMD5AndDESByteEncryptor();
    }
    
}
