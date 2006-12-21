package org.jasypt.salt;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.jasypt.exceptions.EncryptionInitializationException;

public final class SaltGeneration {
    
    private static String SECURE_RANDOM_ALGORITHM = "SHA1PRNG";
    private static SecureRandom random = null;
    
    
    static {
        try {
            random = SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM);
            random.setSeed(System.currentTimeMillis());
        } catch (NoSuchAlgorithmException e) {
            throw new EncryptionInitializationException(e);
        }
    }
    
    
    public static byte[] generateSalt(int lengthBytes) {
        byte[] salt = new byte[lengthBytes];
        synchronized (random) {
            random.nextBytes(salt);
        }
        return salt;
    }
    
    
    private SaltGeneration() {}
    
}
