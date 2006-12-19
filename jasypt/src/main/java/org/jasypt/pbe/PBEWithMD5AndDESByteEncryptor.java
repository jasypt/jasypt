package org.jasypt.pbe;


public final class PBEWithMD5AndDESByteEncryptor extends AbstractPBEByteEncryptor {
    
    private static final String ALGORITHM = "PBEWithMD5AndDES";
    private static final int SALT_SIZE_BYTES = 8;
    
    
    protected String getAlgorithm() {
        return ALGORITHM;
    }
    protected int getSaltSizeBytes() {
        return SALT_SIZE_BYTES;
    }
    
}

