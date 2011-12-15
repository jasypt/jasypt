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
package org.jasypt.spring31.xml.encryption;

import org.jasypt.spring31.properties.EncryptablePropertyPlaceholderConfigurer;
import org.jasypt.spring31.properties.EncryptablePropertySourcesPlaceholderConfigurer;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * 
 * @since 1.9.0
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
final class EncryptablePropertyPlaceholderBeanDefinitionParser 
        extends AbstractEncryptablePropertyLoadingBeanDefinitionParser {

    private static final String SYSTEM_PROPERTIES_MODE_ATTRIBUTE = "system-properties-mode";
    private static final String ENCRYPTOR_ATTRIBUTE = "encryptor";

    private static final String SYSTEM_PROPERTIES_MODE_DEFAULT = "ENVIRONMENT";
    
    
    EncryptablePropertyPlaceholderBeanDefinitionParser() {
        super();
    }

    
    @Override
    protected Class<?> getBeanClass(final Element element) {
        // As of Spring 3.1, the default value of system-properties-mode has changed from
        // 'FALLBACK' to 'ENVIRONMENT'. This latter value indicates that resolution of
        // placeholders against system properties is a function of the Environment and
        // its current set of PropertySources
        if (element.getAttribute(SYSTEM_PROPERTIES_MODE_ATTRIBUTE).equals(SYSTEM_PROPERTIES_MODE_DEFAULT)) {
            return EncryptablePropertySourcesPlaceholderConfigurer.class;
        }

        // the user has explicitly specified a value for system-properties-mode. Revert
        // to PropertyPlaceholderConfigurer to ensure backward compatibility.
        return EncryptablePropertyPlaceholderConfigurer.class;
    }

    
    
    @Override
    protected void doParse(final Element element, final BeanDefinitionBuilder builder) {

        super.doParse(element, builder);

        builder.addPropertyValue("ignoreUnresolvablePlaceholders",
                Boolean.valueOf(element.getAttribute("ignore-unresolvable")));

        String systemPropertiesModeName = element.getAttribute("system-properties-mode");
        if (StringUtils.hasLength(systemPropertiesModeName) &&
                !systemPropertiesModeName.equals(SYSTEM_PROPERTIES_MODE_DEFAULT)) {
            builder.addPropertyValue("systemPropertiesModeName", "SYSTEM_PROPERTIES_MODE_"+systemPropertiesModeName);
        }

        final String encryptorBeanName = element.getAttribute(ENCRYPTOR_ATTRIBUTE);
        if (StringUtils.hasText(encryptorBeanName)) {
            builder.addConstructorArgReference(encryptorBeanName);
        }
        
    }
    
    
}


