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
package org.jasypt.spring3.xml.encryption;

import java.io.IOException;
import java.util.Properties;

import org.jasypt.properties.EncryptableProperties;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.io.support.PropertiesLoaderSupport;

/**
 * 
 * @since 1.9.0
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
public final class EncryptablePropertiesFactoryBean 
        extends PropertiesLoaderSupport
        implements FactoryBean, InitializingBean {

    private boolean singleton = true;
    private Properties singletonInstance;
    
    
    
    public EncryptablePropertiesFactoryBean() {
        super();
    }
    
    

    public final void setSingleton(boolean singleton) {
        this.singleton = singleton;
    }
    
    
    public final boolean isSingleton() {
        return this.singleton;
    }
    
    
    public final void afterPropertiesSet() throws IOException {
        if (this.singleton) {
            this.singletonInstance = processEncryptable(mergeProperties());
        }
    }
    
    
    public final Object getObject() throws IOException {
        if (this.singleton) {
            return this.singletonInstance;
        }
        return processEncryptable(mergeProperties());
    }
    
    public Class getObjectType() {
        return EncryptableProperties.class;
    }

    
    
    private static Properties processEncryptable(final Properties props) {
        return props;
    }
    
}

