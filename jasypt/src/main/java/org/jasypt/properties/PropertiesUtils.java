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

import org.apache.commons.lang.StringUtils;
import org.jasypt.encryption.StringEncryptor;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;

/**
 * <p>
 * Utility class to deal with values in properties files which could be
 * encrypted.
 * </p>
 * <p>
 * A value is considered "encrypted" when it appears surrounded by 
 * <tt>ENC{...}</tt>, like:
 * </p>
 * <p>
 *   <center>
 *     <tt>my.value=ENC{$!"DGAS24FaIO$}</tt>
 *   </center>
 * </p>
 * <p>
 *   <b>This class is NOT meant to be used directly outside of jasypt.</b>
 * </p>
 * 
 * @since 1.4
 * 
 * @author Daniel Fern&aacute;ndez Garrido
 * 
 */
public class PropertiesUtils {

    private static final String ENCRYPTED_VALUE_PREFIX = "ENC{";
    private static final String ENCRYPTED_VALUE_SUFFIX = "}";

    
    private static boolean isEncryptedValue(String value) {
        return (value.startsWith(ENCRYPTED_VALUE_PREFIX) && 
                value.endsWith(ENCRYPTED_VALUE_SUFFIX));
    }
    
    private static String getInnerEncryptedValue(String value) {
        return value.substring(
                ENCRYPTED_VALUE_PREFIX.length(),
                (value.length() - ENCRYPTED_VALUE_SUFFIX.length()));
    }

    
    public static String getComputedValue(
            String originalValue, StringEncryptor encryptor) {
        
        if (originalValue == null || !isEncryptedValue(originalValue.trim())) {
            return originalValue;
        }
        return encryptor.decrypt(getInnerEncryptedValue(originalValue.trim()));
        
    }
    
    
    private PropertiesUtils() {
        super();
    }

    
    public static void main(String[] args) {
        
        StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
        encryptor.setPassword("daniel");
        System.out.println(encryptor.encrypt("HOLA"));
        
        System.out.println(getComputedValue("HOLA", encryptor));
        System.out.println(getComputedValue("ENC{7y8QnPycD3ufR2hkEszGOw==}", encryptor));
        
    }
    
}
