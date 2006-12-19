package org.jasypt.pbe;


public final class PBEWithSHA1AndRC2_40ByteEncryptor extends AbstractPBEByteEncryptor {
    
    private static final String ALGORITHM = "PBEWithSHA1AndRC2_40";
    private static final int SALT_SIZE_BYTES = 8;
    
    
    protected String getAlgorithm() {
        return ALGORITHM;
    }
    protected int getSaltSizeBytes() {
        return SALT_SIZE_BYTES;
    }
    
}

