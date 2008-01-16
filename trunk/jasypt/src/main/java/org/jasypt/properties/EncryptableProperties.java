/*
 * =============================================================================
 * 
 *   Copyright (c) 2007-2008, The JASYPT team (http://www.jasypt.org)
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
package org.jasypt.properties;

import java.util.Properties;

import org.apache.commons.lang.Validate;
import org.jasypt.encryption.StringEncryptor;
import org.jasypt.util.text.TextEncryptor;



/**
 * <p>
 * Subclass of <tt>java.util.Properties</tt> which can make use of a 
 * {@link org.jasypt.encryption.StringEncryptor} or 
 * {@link org.jasypt.util.text.TextEncryptor} object to decrypt property values
 * if they are encrypted in the <tt>.properties</tt> file.
 * </p>
 * <p>
 * A value is considered "encrypted" when it appears surrounded by 
 * <tt>ENC(...)</tt>, like:
 * </p>
 * <p>
 *   <center>
 *     <tt>my.value=ENC(!"DGAS24FaIO$)</tt>
 *   </center>
 * </p>
 * <p>
 * Decryption is performed on-the-fly when the {@link #getProperty(String)} or 
 * {@link #getProperty(String, String)} methods are called, and only these two
 * methods perform decryption (note that neither {@link #get(Object)} nor
 * {@link #toString()} do). Load and store operations are not affected 
 * by decryption in any manner.
 * </p>
 * <p>
 * Encrypted and unencrypted objects can be combined in the same 
 * properties file.
 * </p>
 * 
 * @since 1.4
 * 
 * @author Daniel Fern&aacute;ndez Garrido
 * 
 */
public class EncryptableProperties extends Properties {

    private static final long serialVersionUID = 6479795856725500639L;

    /*
     * Only one of these instances will be initialized, the other one will
     * be null.
     */
    private final StringEncryptor stringEncryptor;
    private final TextEncryptor textEncryptor;
    

    /**
     * <p>
     * Creates an <tt>EncryptableProperties</tt> instance which will use
     * the passed {@link StringEncryptor} object to decrypt encrypted values.
     * </p>
     * 
     * @param stringEncryptor the {@link StringEncryptor} to be used do decrypt
     *                        values. It can not be null.
     */
    public EncryptableProperties(StringEncryptor stringEncryptor) {
        this(null, stringEncryptor);
    }
    

    /**
     * <p>
     * Creates an <tt>EncryptableProperties</tt> instance which will use
     * the passed {@link TextEncryptor} object to decrypt encrypted values.
     * </p>
     * 
     * @param textEncryptor the {@link TextEncryptor} to be used do decrypt
     *                      values. It can not be null.
     */
    public EncryptableProperties(TextEncryptor textEncryptor) {
        this(null, textEncryptor);
    }
    

    /**
     * <p>
     * Creates an <tt>EncryptableProperties</tt> instance which will use
     * the passed {@link StringEncryptor} object to decrypt encrypted values,
     * and the passed defaults as default values (may contain encrypted values).
     * </p>
     * 
     * @param defaults default values for properties (may be encrypted).
     * @param stringEncryptor the {@link StringEncryptor} to be used do decrypt
     *                        values. It can not be null.
     */
    public EncryptableProperties(Properties defaults, StringEncryptor stringEncryptor) {
        super(defaults);
        Validate.notNull(stringEncryptor, "Encryptor cannot be null");
        this.stringEncryptor = stringEncryptor;
        this.textEncryptor = null;
    }


    /**
     * <p>
     * Creates an <tt>EncryptableProperties</tt> instance which will use
     * the passed {@link TextEncryptor} object to decrypt encrypted values,
     * and the passed defaults as default values (may contain encrypted values).
     * </p>
     * 
     * @param defaults default values for properties (may be encrypted).
     * @param textEncryptor the {@link TextEncryptor} to be used do decrypt
     *                      values. It can not be null.
     */
    public EncryptableProperties(Properties defaults, TextEncryptor textEncryptor) {
        super(defaults);
        Validate.notNull(textEncryptor, "Encryptor cannot be null");
        this.stringEncryptor = null;
        this.textEncryptor = textEncryptor;
    }


    /**
     * <p>
     * Obtains the property value for the specified key (see 
     * {@link Properties#getProperty(String)}), decrypting it if needed.
     * </p>
     * 
     * @param key the property key
     * @return the (decrypted) value
     */
    public String getProperty(String key) {
        return decode(super.getProperty(key));
    }
    

    /**
     * <p>
     * Obtains the property value for the specified key (see 
     * {@link Properties#getProperty(String)}), decrypting it if needed.
     * </p>
     * <p>
     * If no value is found for the specified key, the default value will
     * be returned (decrypted if needed).
     * </p>
     * 
     * @param key the property key
     * @param defaultValue the default value to return
     * @return the (decrypted) value
     */
    public String getProperty(String key, String defaultValue) {
        return decode(super.getProperty(key, defaultValue));
    }
    

    /*
     * Internal method for decoding (decrypting) a value if needed.
     */
    private synchronized String decode(String encodedValue) {
        if (!PropertyValueEncryptionUtils.isEncryptedValue(encodedValue)) {
            return encodedValue;
        }
        if (this.stringEncryptor != null) {
            return PropertyValueEncryptionUtils.decrypt(encodedValue, this.stringEncryptor);
            
        }
        return PropertyValueEncryptionUtils.decrypt(encodedValue, this.textEncryptor);
    }

    
    
}
