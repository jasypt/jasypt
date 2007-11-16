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
package org.jasypt.properties;

import org.jasypt.encryption.StringEncryptor;
import org.jasypt.util.text.TextEncryptor;

/**
 * <p>
 * Utility class to decode/encode values in properties files which could be
 * encrypted.
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
 *   <b>Do NOT use this class. It is meant for internal Jasypt use only.</b>
 * </p>
 * 
 * @since 1.4
 * 
 * @author Daniel Fern&aacute;ndez Garrido
 * 
 */
public class PropertyDecodingUtils {

    private static final String ENCRYPTED_VALUE_PREFIX = "ENC(";
    private static final String ENCRYPTED_VALUE_SUFFIX = ")";

    
    public static boolean isEncryptedValue(String value) {
        if (value == null) {
            return false;
        }
        String trimmedValue = value.trim();
        return (trimmedValue.startsWith(ENCRYPTED_VALUE_PREFIX) && 
                trimmedValue.endsWith(ENCRYPTED_VALUE_SUFFIX));
    }
    
    private static String getInnerEncryptedValue(String value) {
        return value.substring(
                ENCRYPTED_VALUE_PREFIX.length(),
                (value.length() - ENCRYPTED_VALUE_SUFFIX.length()));
    }

    
    public static String decode(
            String encodedValue, StringEncryptor encryptor) {
        return encryptor.decrypt(getInnerEncryptedValue(encodedValue.trim()));
    }

    
    public static String decode(
            String encodedValue, TextEncryptor encryptor) {
        return encryptor.decrypt(getInnerEncryptedValue(encodedValue.trim()));
    }

    
    public static String encode(
            String decodedValue, StringEncryptor encryptor) {
        return 
            ENCRYPTED_VALUE_PREFIX + 
            encryptor.encrypt(decodedValue) +
            ENCRYPTED_VALUE_SUFFIX;
    }

    
    public static String encode(
            String decodedValue, TextEncryptor encryptor) {
        return 
            ENCRYPTED_VALUE_PREFIX + 
            encryptor.encrypt(decodedValue) +
            ENCRYPTED_VALUE_SUFFIX;
    }
    
    
    private PropertyDecodingUtils() {
        super();
    }

    
}
