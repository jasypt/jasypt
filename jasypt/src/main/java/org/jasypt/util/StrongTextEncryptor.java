package org.jasypt.util;

import org.jasypt.encryption.pbe.PBEWithMD5AndTripleDESStringEncryptor;

public final class StrongTextEncryptor implements TextEncryptor {

    
    private PBEWithMD5AndTripleDESStringEncryptor encryptor = null;
    
    
    public StrongTextEncryptor() {
        this.encryptor = new PBEWithMD5AndTripleDESStringEncryptor();
    }
    
    /* (non-Javadoc)
     * @see org.jasypt.util.TextEncryptor#setPassword(java.lang.String)
     */
    public synchronized void setPassword(String password) {
        encryptor.setPassword(password);
    }

    
    /* (non-Javadoc)
     * @see org.jasypt.util.TextEncryptor#encrypt(java.lang.String)
     */
    public synchronized String encrypt(String message) {
        return encryptor.encrypt(message);
    }
    
    /* (non-Javadoc)
     * @see org.jasypt.util.TextEncryptor#decrypt(java.lang.String)
     */
    public synchronized String decrypt(String encryptedMessage) {
        return encryptor.decrypt(encryptedMessage);
    }
    
}
