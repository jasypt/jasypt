/*
 * =============================================================================
 * 
 *   Copyright (c) 2007-2010, The JASYPT team (http://www.jasypt.org)
 * 
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 * 
 *       http://www.apache.org/licenses/LICENSE-2.0
 * 
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 * 
 * =============================================================================
 */
package org.jasypt.wicket13;

import org.apache.wicket.WicketRuntimeException;
import org.apache.wicket.util.crypt.Base64UrlSafe;
import org.apache.wicket.util.crypt.ICrypt;
import org.jasypt.encryption.pbe.PBEByteEncryptor;


/**
 * <p>
 * Jasypt's implementation of {@link ICrypt}, based on the use of a 
 * {@link PBEByteEncryptor} object for encryption and decryption operations.
 * </p>
 * <p>
 * This class is <i>thread-safe</i>.
 * </p>
 * 
 * @since 1.9.0
 * @author Daniel Fern&aacute;ndez
 *
 */
public final class JasyptCrypt implements ICrypt {

    // Encoding used to convert java String from and to byte[]
    private static final String CHARACTER_ENCODING = "UTF-8";

    // The wrapped encryptor 
    private final PBEByteEncryptor encryptor;

    
    /**
     * <p>
     * Creates a new <tt>JasyptCrypt</tt> object, wrapping the passed
     * encryptor.
     * </p>
     * 
     * @param encryptor the PBEByteEncryptor to be used internally.
     */
    public JasyptCrypt(final PBEByteEncryptor encryptor) {
        this.encryptor = encryptor;
    }
    

    /**
     * <p>
     * Decrypts a string using URL and filename safe Base64 decoding.
     * </p>
     * 
     * @param text the text to be decrypted.
     * @return the decrypted string.
     */
    public String decryptUrlSafe(final String text) {
        
        try {
            final byte[] base64EncryptedBytes = text.getBytes();
            final byte[] encryptedBytes = 
                Base64UrlSafe.decodeBase64(base64EncryptedBytes);
            return new String(
                    this.encryptor.decrypt(encryptedBytes), CHARACTER_ENCODING);
        } catch (Exception e) {
            throw new WicketRuntimeException(e);
        }
        
    }

    
    /**
     * <p>
     * Encrypts a string using URL and filename safe Base64 encoding.
     * </p>
     * 
     * @param plainText the text to be encrypted.
     * @return encrypted string.
     */
    public String encryptUrlSafe(final String plainText) {
        
        try {
            final byte[] plainBytes = plainText.getBytes(CHARACTER_ENCODING); 
            final byte[] encryptedBytes = this.encryptor.encrypt(plainBytes);
            return new String(Base64UrlSafe.encodeBase64(encryptedBytes));
        } catch (Exception e) {
            throw new WicketRuntimeException(e);
        }
        
    }

    
    /**
     * <p>
     * <b>Important</b>: Using jasypt, it makes no sense to change the encryption 
     * key once the encryptor has been initialized, and so this method is
     * implemented to throw <tt>UnsupportedOperationException</tt> always.
     * </p>
     */
    public void setKey(final String key) {
        throw new UnsupportedOperationException(
                "JasyptCrypt encryptors cannot be set password by calling " +
                ICrypt.class.getName() + ".setKey()");
    }

}
