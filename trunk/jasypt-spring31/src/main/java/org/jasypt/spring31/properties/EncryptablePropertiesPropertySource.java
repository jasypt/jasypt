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

import org.jasypt.properties.EncryptableProperties;
import org.springframework.core.env.EnumerablePropertySource;

/**
 * 
 * @since 1.9.0
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
public final class EncryptablePropertiesPropertySource 
        extends EnumerablePropertySource<EncryptableProperties> {


    // TODO Do we really need this? Wouldn't we do with a PopertiesPropertySource containing
    // an EncryptableProperties?
        
    public EncryptablePropertiesPropertySource(final String name, final EncryptableProperties props) {
        super(name, props);
    }
    
    
    @Override
    public String[] getPropertyNames() {
        return getSource().keySet().toArray(new String[0]);
    }

    @Override
    public Object getProperty(final String propertyName) {
        return getSource().getProperty(propertyName);
    }
    

    
}
