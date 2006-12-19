package org.jasypt.encryption.pbe;



public final class PBEWithMD5AndTripleDESStringEncryptor 
        extends AbstractPBEStringEncryptor {

    protected AbstractPBEByteEncryptor createByteEncryptorInstance() {
        return new PBEWithMD5AndTripleDESByteEncryptor();
    }
    
}
