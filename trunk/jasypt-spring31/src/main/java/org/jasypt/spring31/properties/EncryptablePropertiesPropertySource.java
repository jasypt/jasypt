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
package org.jasypt.spring31.properties;

import java.util.Properties;

import org.jasypt.encryption.StringEncryptor;
import org.jasypt.properties.EncryptableProperties;
import org.jasypt.util.text.TextEncryptor;
import org.springframework.core.env.PropertiesPropertySource;

/**
 * 
 * @since 1.9.0
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
public final class EncryptablePropertiesPropertySource 
        extends PropertiesPropertySource {


    public EncryptablePropertiesPropertySource(final String name, final EncryptableProperties props) {
        super(name, props);
    }

    public EncryptablePropertiesPropertySource(final String name, final Properties props, final TextEncryptor encryptor) {
        super(name, processProperties(props, encryptor));
    }

    public EncryptablePropertiesPropertySource(final String name, final Properties props, final StringEncryptor encryptor) {
        super(name, processProperties(props, encryptor));
    }

    
    private static Properties processProperties(final Properties props, final TextEncryptor encryptor) {
        if (props == null) {
            return null;
        }
        if (props instanceof EncryptableProperties) {
            throw new IllegalArgumentException(
                    "Properties object already is an " + EncryptableProperties.class.getName() + 
                    " object. No encryptor should be specified.");
        }
        final EncryptableProperties encryptableProperties = new EncryptableProperties(encryptor);
        encryptableProperties.putAll(props);
        return encryptableProperties;
    }

    
    private static Properties processProperties(final Properties props, final StringEncryptor encryptor) {
        if (props == null) {
            return null;
        }
        if (props instanceof EncryptableProperties) {
            throw new IllegalArgumentException(
                    "Properties object already is an " + EncryptableProperties.class.getName() + 
                    " object. No encryptor should be specified.");
        }
        final EncryptableProperties encryptableProperties = new EncryptableProperties(encryptor);
        encryptableProperties.putAll(props);
        return encryptableProperties;
    }
    
}
