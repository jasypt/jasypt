package org.jasypt.encryption.pbe;


public final class PBEWithSHA1AndDESedeByteEncryptor extends AbstractPBEByteEncryptor {
    
    private static final String ALGORITHM = "PBEWithSHA1AndDESede";
    private static final int SALT_SIZE_BYTES = 8;
    
    
    protected String getAlgorithm() {
        return ALGORITHM;
    }
    protected int getSaltSizeBytes() {
        return SALT_SIZE_BYTES;
    }
    
}

