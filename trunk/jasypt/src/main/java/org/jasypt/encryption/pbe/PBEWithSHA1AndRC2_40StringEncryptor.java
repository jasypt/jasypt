package org.jasypt.encryption.pbe;



public final class PBEWithSHA1AndRC2_40StringEncryptor 
        extends AbstractPBEStringEncryptor {

    protected AbstractPBEByteEncryptor createByteEncryptorInstance() {
        return new PBEWithSHA1AndRC2_40ByteEncryptor();
    }
    
}
