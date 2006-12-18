package org.jasypt.salt;

import java.util.Random;

public final class SaltGeneration {
    
    private static Random random = null;
    
    
    static {
        random = new Random(System.currentTimeMillis());
    }
    
    
    public static synchronized byte[] generateSalt(int lengthBytes) {
        byte[] salt = new byte[lengthBytes];
        random.nextBytes(salt);
        return salt;
    }
    
    
    private SaltGeneration() {}
    
}
