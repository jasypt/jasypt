/*
 * =============================================================================
 * 
 *   Copyright (c) 2007, The JASYPT team (http://www.jasypt.org)
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
package org.jasypt.wicket;

import org.apache.wicket.WicketRuntimeException;
import org.apache.wicket.util.crypt.Base64UrlSafe;
import org.apache.wicket.util.crypt.ICrypt;
import org.jasypt.encryption.pbe.PBEByteEncryptor;


/**
 * 
 * 
 * <p>
 * This class is <i>thread-safe</i>.
 * </p>
 * 
 * @since 1.4
 * @author Daniel Fern&aacute;ndez Garrido
 *
 */
public class JasyptCrypt implements ICrypt {

    /** Encoding used to convert java String from and to byte[] */
    private static final String CHARACTER_ENCODING = "UTF-8";

    private final PBEByteEncryptor encryptor;

    
    public JasyptCrypt(PBEByteEncryptor encryptor) {
        this.encryptor = encryptor;
    }
    
    
    public String decryptUrlSafe(String text) {
        
        try {
            byte[] base64EncryptedBytes = text.getBytes();
            byte[] encryptedBytes = 
                Base64UrlSafe.decodeBase64(base64EncryptedBytes);
            return new String(
                    this.encryptor.decrypt(encryptedBytes), CHARACTER_ENCODING);
        } catch (Exception e) {
            throw new WicketRuntimeException(e);
        }
        
    }

    public String encryptUrlSafe(String plainText) {
        
        try {
            byte[] plainBytes = plainText.getBytes(CHARACTER_ENCODING); 
            byte[] encryptedBytes = this.encryptor.encrypt(plainBytes);
            return new String(Base64UrlSafe.encodeBase64(encryptedBytes));
        } catch (Exception e) {
            throw new WicketRuntimeException(e);
        }
        
    }

    public void setKey(final String key) {
        throw new UnsupportedOperationException(
                "JasyptCrypt encryptors cannot be set password by calling " +
                ICrypt.class.getName() + ".setKey()");
    }

}
