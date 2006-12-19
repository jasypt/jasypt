package org.jasypt.pbe;


public final class PBEWithMD5AndTripleDESByteEncryptor extends AbstractPBEByteEncryptor {
    
    private static final String ALGORITHM = "PBEWithMD5AndTripleDES";
    private static final int SALT_SIZE_BYTES = 8;
    
    
    protected String getAlgorithm() {
        return ALGORITHM;
    }
    protected int getSaltSizeBytes() {
        return SALT_SIZE_BYTES;
    }
    
}

