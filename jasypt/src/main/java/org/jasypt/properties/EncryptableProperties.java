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
package org.jasypt.properties;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectOutputStream;
import java.util.Hashtable;
import java.util.Properties;

import org.jasypt.commons.CommonUtils;
import org.jasypt.encryption.StringEncryptor;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
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
 * <p>
 * Please note that, altough objects of this class are Serializable, they
 * cannot be serialized and then de-serialized in different classloaders or
 * virtual machines. This is so because encryptors are not serializable themselves
 * (they cannot, as they contain sensitive information) and so they remain
 * in memory, and live for as long as the classloader lives.
 * </p>
 * 
 * @since 1.4
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
public final class EncryptableProperties extends Properties {

    private static final long serialVersionUID = 6479795856725500639L;

    /*
     * Used as an identifier for the encryptor registry
     */
    private final Integer ident = new Integer(CommonUtils.nextRandomInt());
    
    /*
     * Used as a marker to know if the object has ever been serialized
     */
    private boolean beenSerialized = false;

    
    /**
     * <p>
     * Creates an <tt>EncryptableProperties</tt> instance which will use
     * the passed {@link StringEncryptor} object to decrypt encrypted values.
     * </p>
     * 
     * @param stringEncryptor the {@link StringEncryptor} to be used do decrypt
     *                        values. It can not be null.
     */
    public EncryptableProperties(final StringEncryptor stringEncryptor) {
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
    public EncryptableProperties(final TextEncryptor textEncryptor) {
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
    public EncryptableProperties(final Properties defaults, final StringEncryptor stringEncryptor) {
        super(defaults);
        CommonUtils.validateNotNull(stringEncryptor, "Encryptor cannot be null");
        final EncryptablePropertiesEncryptorRegistry registry =
            EncryptablePropertiesEncryptorRegistry.getInstance();
        registry.setStringEncryptor(this, stringEncryptor);
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
    public EncryptableProperties(final Properties defaults, final TextEncryptor textEncryptor) {
        super(defaults);
        CommonUtils.validateNotNull(textEncryptor, "Encryptor cannot be null");
        final EncryptablePropertiesEncryptorRegistry registry =
            EncryptablePropertiesEncryptorRegistry.getInstance();
        registry.setTextEncryptor(this, textEncryptor);
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
    public String getProperty(final String key) {
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
    public String getProperty(final String key, final String defaultValue) {
        return decode(super.getProperty(key, defaultValue));
    }


    /**
     * <p>
     * Obtains the property value for the specified key (see 
     * {@link Hashtable#get(Object)}), decrypting it if needed.
     * </p>
     * 
     * @param key the property key
     * @return the (decrypted) value
     * @since 1.9.0
     */
    public synchronized Object get(final Object key) {
        final Object value = super.get(key);
        final String valueStr = 
                (value instanceof String) ? (String)value : null;
        return decode(valueStr);
    }
    
    
    /*
     *  Returns the identifier, just to be used by the registry
     */
    Integer getIdent() {
        return this.ident;
    }
    

    /*
     * Internal method for decoding (decrypting) a value if needed.
     */
    private synchronized String decode(final String encodedValue) {
        
        if (!PropertyValueEncryptionUtils.isEncryptedValue(encodedValue)) {
            return encodedValue;
        }
        final EncryptablePropertiesEncryptorRegistry registry =
            EncryptablePropertiesEncryptorRegistry.getInstance();
        final StringEncryptor stringEncryptor = registry.getStringEncryptor(this);
        if (stringEncryptor != null) {
            return PropertyValueEncryptionUtils.decrypt(encodedValue, stringEncryptor);
            
        }
        final TextEncryptor textEncryptor = registry.getTextEncryptor(this);
        if (textEncryptor != null) {
            return PropertyValueEncryptionUtils.decrypt(encodedValue, textEncryptor);
        }
        
        /*
         * If neither a StringEncryptor nor a TextEncryptor can be retrieved
         * from the registry, this means that this EncryptableProperties
         * object has been serialized and then deserialized in a different
         * classloader and virtual machine, which is an unsupported behaviour. 
         */
        throw new EncryptionOperationNotPossibleException(
                "Neither a string encryptor nor a text encryptor exist " +
                "for this instance of EncryptableProperties. This is usually " +
                "caused by the instance having been serialized and then " +
                "de-serialized in a different classloader or virtual machine, " +
                "which is an unsupported behaviour (as encryptors cannot be " +
                "serialized themselves)");
        
    }
    

    
    private void writeObject(final ObjectOutputStream outputStream) throws IOException {
        this.beenSerialized = true;
        outputStream.defaultWriteObject();
    }
    
    
    
    protected void finalize() throws Throwable {
        if (!this.beenSerialized) {
            final EncryptablePropertiesEncryptorRegistry registry =
                EncryptablePropertiesEncryptorRegistry.getInstance();
            registry.removeEntries(this);
        }
    }

    
}
