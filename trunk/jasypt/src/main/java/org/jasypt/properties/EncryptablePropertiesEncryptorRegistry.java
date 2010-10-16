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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.jasypt.encryption.StringEncryptor;
import org.jasypt.util.text.TextEncryptor;

/*
 * This class acts as a classloader-wide in-memory registry for encryptors, so that
 * EncryptableProperties instances can be safely serialized (encryptors are not
 * serializable).
 * 
 * This means that an EncryptableProperties instance will be de-serializable 
 * only by the same virtual machine that serialized it.
 * 
 * @since 1.5
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
final class EncryptablePropertiesEncryptorRegistry {

    private static final EncryptablePropertiesEncryptorRegistry instance =
        new EncryptablePropertiesEncryptorRegistry();
    
    private final Map stringEncryptors = Collections.synchronizedMap(new HashMap());
    private final Map textEncryptors = Collections.synchronizedMap(new HashMap());
    
    
    static EncryptablePropertiesEncryptorRegistry getInstance() {
        return instance;
    }
    
    
    private EncryptablePropertiesEncryptorRegistry() {
        super();
    }

    
    void removeEntries(final EncryptableProperties prop) {
        this.stringEncryptors.remove(prop.getIdent());
        this.textEncryptors.remove(prop.getIdent());
    }
    
    
    StringEncryptor getStringEncryptor(final EncryptableProperties prop) {
        return (StringEncryptor) this.stringEncryptors.get(prop.getIdent());
    }
    
    
    void setStringEncryptor(final EncryptableProperties prop, final StringEncryptor encryptor) {
        this.stringEncryptors.put(prop.getIdent(), encryptor);
    }

    
    TextEncryptor getTextEncryptor(final EncryptableProperties prop) {
        return (TextEncryptor) this.textEncryptors.get(prop.getIdent());
    }
    
    
    void setTextEncryptor(final EncryptableProperties prop, final TextEncryptor encryptor) {
        this.textEncryptors.put(prop.getIdent(), encryptor);
    }
    
}
