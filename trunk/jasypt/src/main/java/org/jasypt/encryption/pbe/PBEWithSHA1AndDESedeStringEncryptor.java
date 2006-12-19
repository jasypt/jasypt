package org.jasypt.encryption.pbe;



public final class PBEWithSHA1AndDESedeStringEncryptor 
        extends AbstractPBEStringEncryptor {

    protected AbstractPBEByteEncryptor createByteEncryptorInstance() {
        return new PBEWithSHA1AndDESedeByteEncryptor();
    }
    
}
